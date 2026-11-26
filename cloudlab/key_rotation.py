"""Cross-site key rotation and per-snapshot readability acceptance.

The key service's rotation receipt proves only what one site reported at one
moment; a decrypt probe proves only one attempted read of one copy.  This
module joins the independent originals -- :mod:`cloudlab.key_wrap` envelopes,
:mod:`cloudlab.key_service` receipts, :mod:`cloudlab.decrypt_probe` probes and
the recovery snapshot chain -- into an acceptance decision for every snapshot
the platform still promises recoverable.

Invariants enforced here:

* exactly one key row per claim may be the unique ``current`` version;
* a successful site receipt never substitutes for a per-snapshot read-back;
* a failed probe is classified as ``missing_key``,
  ``wrap_version_mismatch`` / ``wrap_invalid`` or ``ciphertext_corrupt`` only
  with corroborating evidence, otherwise ``undetermined``;
* quarantined snapshots leave the promised-recoverable set (which is what
  permits old-key revocation), while every fact about the failure stays
  append-only;
* old keys in coexistence have bounded purpose/holder/deadline grants that
  cannot be renewed past a hard cap and never renewed after confirmed
  compromise;
* escrow recovery is narrowly scoped to one snapshot in one bounded window and
  needs separate contact/access and destruction proofs;
* issued reports are immutable versions; supplemental evidence is appended and
  can never rewrite the failure the customer actually met.

The entry point is :func:`run` (op-dispatch, same style as the other workflow
modules).  Rich query functions and thin named wrappers are provided as well.
"""
import json

from .store import audit_run
from . import key_wrap, key_service, decrypt_probe
from . import recovery

# outcomes in decrypt_probes that count as a real successful read
SUCCESS_OUTCOMES = {'success', 'succeeded', 'ok', 'decrypted', 'readable'}
FAILURE_OUTCOMES = {'failed', 'failure', 'error', 'denied'}
DONE_RESULTS = {'done', 'recorded', 'ok', 'success', 'complete', 'completed'}

MISSING_KEY = 'missing_key'
WRAP_VERSION_MISMATCH = 'wrap_version_mismatch'
WRAP_INVALID = 'wrap_invalid'
CIPHERTEXT_CORRUPT = 'ciphertext_corrupt'
UNDETERMINED = 'undetermined'

CLASSIFICATIONS = (MISSING_KEY, WRAP_VERSION_MISMATCH, WRAP_INVALID,
                   CIPHERTEXT_CORRUPT, UNDETERMINED)

DEFAULT_TTL = 30          # minutes an old key may linger by default
DEFAULT_HARD_TTL = 120    # absolute renewal cap after rotation
DEFAULT_ESCROW_WINDOW = 15
MAX_ESCROW_WINDOW = 60

_DDL = [
    """CREATE TABLE IF NOT EXISTS kr_keys(
        key_id TEXT PRIMARY KEY, claim_id TEXT NOT NULL, epoch INTEGER NOT NULL,
        state TEXT NOT NULL, replaces TEXT, created_at INTEGER, rotate_id TEXT,
        deadline INTEGER, hard_deadline INTEGER, purposes TEXT, holders TEXT,
        compromise INTEGER NOT NULL DEFAULT 0, compromise_at INTEGER,
        revoke_status TEXT, revoke_at INTEGER, revoke_receipt TEXT,
        destruction_proof TEXT, destroyed_at INTEGER)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS kr_one_current ON kr_keys(claim_id) WHERE state='current'",
    """CREATE TABLE IF NOT EXISTS kr_rotations(
        id TEXT PRIMARY KEY, claim_id TEXT NOT NULL, from_key TEXT, to_key TEXT,
        at INTEGER, state TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_targets(
        id TEXT PRIMARY KEY, rotation_id TEXT, claim_id TEXT, kind TEXT,
        ref_id TEXT, site TEXT, wrap_id TEXT, state TEXT, detail TEXT,
        UNIQUE(rotation_id, kind, ref_id, site))""",
    """CREATE TABLE IF NOT EXISTS kr_acceptance(
        snapshot_id TEXT PRIMARY KEY, claim_id TEXT, state TEXT,
        classification TEXT, key_id TEXT, readback_probe TEXT,
        readback_at INTEGER, site TEXT, since INTEGER, reason TEXT,
        window_id TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_events(
        id TEXT PRIMARY KEY, claim_id TEXT, snapshot_id TEXT, at INTEGER,
        kind TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_assessments(
        id TEXT PRIMARY KEY, probe_id TEXT, snapshot_id TEXT, claim_id TEXT,
        at INTEGER, classification TEXT, basis TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_obs(
        id TEXT PRIMARY KEY, claim_id TEXT, snapshot_id TEXT, site TEXT,
        at INTEGER, kind TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_windows(
        id TEXT PRIMARY KEY, claim_id TEXT, key_id TEXT, mode TEXT,
        holder TEXT, site TEXT, purposes TEXT, refs TEXT, start INTEGER,
        deadline INTEGER, state TEXT, env_id TEXT, access_proof TEXT,
        accessed_at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS kr_access_events(
        id TEXT PRIMARY KEY, window_id TEXT, key_id TEXT, claim_id TEXT,
        holder TEXT, purpose TEXT, ref_id TEXT, at INTEGER, proof TEXT,
        result TEXT, reason TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_external(
        id TEXT PRIMARY KEY, key_id TEXT, claim_id TEXT, location TEXT,
        holder TEXT, site TEXT, at INTEGER, disposition TEXT, proof TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_escrow_envs(
        id TEXT PRIMARY KEY, site TEXT, holder TEXT, verified INTEGER,
        proof TEXT, at INTEGER, contact_state TEXT, contact_at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS kr_revocations(
        receipt_id TEXT PRIMARY KEY, key_id TEXT, at INTEGER, site TEXT,
        result TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_reports(
        id TEXT PRIMARY KEY, claim_id TEXT, version INTEGER, at INTEGER,
        overall TEXT, document TEXT)""",
    """CREATE TABLE IF NOT EXISTS kr_certified_plans(
        id TEXT PRIMARY KEY, claim_id TEXT, candidate TEXT, snapshot_id TEXT,
        at INTEGER, detail TEXT)""",
    # mirrors of the seeded raw tables, created here too so read models work
    # on a fresh database before any seed recorder was ever called
    """CREATE TABLE IF NOT EXISTS key_wraps(
        id TEXT PRIMARY KEY, key_id TEXT, claim_id TEXT, snapshot_id TEXT,
        epoch INTEGER, site TEXT, status TEXT)""",
    """CREATE TABLE IF NOT EXISTS key_receipts(
        id TEXT PRIMARY KEY, key_id TEXT, action TEXT, at INTEGER,
        site TEXT, result TEXT)""",
    """CREATE TABLE IF NOT EXISTS decrypt_probes(
        id TEXT PRIMARY KEY, claim_id TEXT, snapshot_id TEXT, key_id TEXT,
        site TEXT, at INTEGER, outcome TEXT)""",
]


def ensure(db):
    for stmt in _DDL:
        db.execute(stmt)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def g(x, *names, default=None):
    """First non-None payload value among aliases."""
    if isinstance(x, dict):
        for n in names:
            if n in x and x[n] is not None:
                return x[n]
    return default


def _at(p):
    return g(p, 'at', 'minute', 'now', 'timestamp', 'when')


def _id(p, *extra):
    return g(p, 'id', 'op_id', *extra)


def _j(value):
    return json.dumps(value if value is not None else [], ensure_ascii=False,
                      sort_keys=True)


def _lj(raw, default=None):
    if raw is None or raw == '':
        return [] if default is None else default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return [] if default is None else default


def _table_exists(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)).fetchone() is not None


def _one(db, sql, args=()):
    return db.execute(sql, args).fetchone()


def _key_row(db, key_id):
    if not key_id:
        return None
    return _one(db, 'SELECT * FROM kr_keys WHERE key_id=?', (key_id,))


def _current_key(db, claim_id):
    row = _one(
        db,
        "SELECT * FROM kr_keys WHERE claim_id=? AND state='current' "
        "ORDER BY epoch DESC LIMIT 1", (claim_id,))
    if row:
        return row
    # best-effort inference from raw rotation receipts when the caller never
    # registered key epochs through this module
    if _table_exists(db, 'key_receipts') and _table_exists(db, 'key_wraps'):
        r = _one(
            db,
            """SELECT r.key_id AS key_id, MAX(r.at) AS at
                 FROM key_receipts r
                WHERE r.action IN ('rotate','rotation','rotated')
                  AND r.result IN ('done','complete','completed','success')
                  AND r.key_id IN (SELECT key_id FROM key_wraps WHERE claim_id=?)
                GROUP BY r.key_id ORDER BY at DESC LIMIT 1""", (claim_id,))
        if r:
            return {'key_id': r['key_id'], 'claim_id': claim_id, 'epoch': None,
                    'state': 'current', 'inferred': 1}
    return None


def _current_key_id(db, claim_id):
    row = _current_key(db, claim_id)
    return row['key_id'] if row else None


def _derive_claim(db, p, snapshot_id=None, key_id=None):
    claim = g(p, 'claim_id', 'claim', 'volume', 'volume_id')
    if claim:
        return claim
    snapshot_id = snapshot_id or g(p, 'snapshot_id', 'snapshot')
    if snapshot_id:
        r = _one(db, 'SELECT claim_id FROM snapshots WHERE id=?',
                 (snapshot_id,)) if _table_exists(db, 'snapshots') else None
        if r and r['claim_id']:
            return r['claim_id']
        r = _one(db, 'SELECT claim_id FROM key_wraps WHERE snapshot_id=? LIMIT 1',
                 (snapshot_id,))
        if r and r['claim_id']:
            return r['claim_id']
        r = _one(db, 'SELECT claim_id FROM kr_acceptance WHERE snapshot_id=?',
                 (snapshot_id,))
        if r and r['claim_id']:
            return r['claim_id']
    key_id = key_id or g(p, 'key_id', 'key')
    if key_id:
        r = _key_row(db, key_id)
        if r:
            return r['claim_id']
        r = _one(db, 'SELECT claim_id FROM key_wraps WHERE key_id=? LIMIT 1',
                 (key_id,))
        if r and r['claim_id']:
            return r['claim_id']
    return None


def _next_seq_id(db, table, id_column, prefix):
    n = db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
    candidate = f'{prefix}:{n + 1}'
    while _one(db, f'SELECT 1 FROM {table} WHERE {id_column}=?', (candidate,)):
        n += 1
        candidate = f'{prefix}:{n + 1}'
    return candidate


def _add_event(db, event_id, claim_id, snapshot_id, at, kind, detail=None):
    if event_id and _one(db, 'SELECT 1 FROM kr_events WHERE id=?', (event_id,)):
        return False
    if not event_id:
        event_id = _next_seq_id(db, 'kr_events', 'id', f'evt-{kind}')
    db.execute('INSERT INTO kr_events VALUES(?,?,?,?,?,?)',
               (event_id, claim_id, snapshot_id, at, kind,
                _j(detail if detail is not None else {})))
    return event_id


def _upsert_acceptance(db, snapshot_id, claim_id, **fields):
    row = _one(db, 'SELECT * FROM kr_acceptance WHERE snapshot_id=?',
               (snapshot_id,))
    if not row:
        db.execute(
            'INSERT INTO kr_acceptance(snapshot_id,claim_id,state) VALUES(?,?,?)',
            (snapshot_id, claim_id, fields.pop('state', 'unverified')))
        row = _one(db, 'SELECT * FROM kr_acceptance WHERE snapshot_id=?',
                   (snapshot_id,))
    sets, vals = [], []
    for k, v in fields.items():
        sets.append(f'{k}=?')
        vals.append(v)
    if sets:
        vals.append(snapshot_id)
        db.execute(f'UPDATE kr_acceptance SET {",".join(sets)} WHERE snapshot_id=?',
                   vals)


# ---------------------------------------------------------------------------
# rotation scope
# ---------------------------------------------------------------------------

def _snapshot_ids(db, claim_id):
    ids = []
    seen = set()

    def add(value):
        if value and value not in seen:
            seen.add(value)
            ids.append(value)

    if _table_exists(db, 'snapshots'):
        for r in db.execute('SELECT id FROM snapshots WHERE claim_id=? ORDER BY generation,id',
                            (claim_id,)):
            add(r['id'])
    for r in db.execute('SELECT snapshot_id FROM key_wraps WHERE claim_id=?',
                        (claim_id,)):
        add(r['snapshot_id'])
    for r in db.execute('SELECT snapshot_id FROM kr_acceptance WHERE claim_id=?',
                        (claim_id,)):
        add(r['snapshot_id'])
    return ids


def _build_targets(db, p, rotation_id, claim_id, from_key, to_key):
    at = _at(p)
    created = []

    def add(kind, ref_id, site=None, wrap_id=None, detail=None):
        tid = f'{rotation_id}:{kind}:{ref_id}' + (f'@{site}' if site else '')
        exists = _one(db, 'SELECT 1 FROM kr_targets WHERE id=?', (tid,))
        if exists:
            return tid
        db.execute('INSERT INTO kr_targets VALUES(?,?,?,?,?,?,?,?,?)',
                   (tid, rotation_id, claim_id, kind, str(ref_id), site,
                    wrap_id, 'in_scope', _j(detail or {})))
        created.append(tid)
        return tid

    # online volume itself
    online_site = g(p, 'online_site', 'primary_site', 'site')
    add('online_volume', g(p, 'online_id', 'volume_id', default='volume'),
        online_site)

    # every envelope in the wrap ledger for this claim
    for r in db.execute('SELECT * FROM key_wraps WHERE claim_id=?', (claim_id,)):
        kind = 'snapshot' if r['snapshot_id'] else 'wrap'
        add(kind, r['snapshot_id'] or r['id'], r['site'], r['id'],
            {'key_id': r['key_id'], 'epoch': r['epoch'], 'status': r['status']})

    # every registered snapshot (catches missing wraps as scope gaps)
    for sid in _snapshot_ids(db, claim_id):
        wrap = _one(
            db,
            'SELECT id,site FROM key_wraps WHERE claim_id=? AND snapshot_id=? LIMIT 1',
            (claim_id, sid))
        add('snapshot', sid, wrap['site'] if wrap else None,
            wrap['id'] if wrap else None)

    # recovery replicas, including offline generations
    if _table_exists(db, 'replicas'):
        for r in db.execute('SELECT * FROM replicas WHERE claim_id=?', (claim_id,)):
            kind = 'offline_replica' if r['state'] in ('offline', 'detached') \
                else 'replica'
            add(kind, r['id'], r['rack'], detail={'generation': r['generation'],
                                                  'state': r['state']})

    # explicit offline replicas / copies
    for item in g(p, 'offline', 'offline_replicas', 'offline_copies', default=[]) or []:
        if isinstance(item, str):
            add('offline_replica', item)
        else:
            add('offline_replica', g(item, 'id', 'ref_id'),
                g(item, 'site'), g(item, 'wrap_id'), item)

    # external wrap / key locations
    for item in g(p, 'external', 'external_copies', 'external_locations',
                  default=[]) or []:
        if isinstance(item, str):
            eid = item
            item = {'id': item}
        else:
            eid = g(item, 'id', 'location_id')
        add('external_wrap', eid, g(item, 'site'), g(item, 'wrap_id'), item)
        if not _one(db, 'SELECT 1 FROM kr_external WHERE id=?', (eid,)):
            db.execute('INSERT INTO kr_external VALUES(?,?,?,?,?,?,?,?,?)',
                       (eid, g(item, 'key_id', 'key', default=from_key),
                        claim_id, g(item, 'location', default=eid),
                        g(item, 'holder'), g(item, 'site'), at, 'open', None))
    return created


def rotation_scope(db, rotation_id=None, claim_id=None):
    ensure(db)
    if rotation_id:
        rot = _one(db, 'SELECT * FROM kr_rotations WHERE id=?', (rotation_id,))
        if not rot:
            return {'decision': 'blocked', 'reason': 'unknown_rotation'}
        claim_id = rot['claim_id']
    elif claim_id:
        rot = _one(db,
                   'SELECT * FROM kr_rotations WHERE claim_id=? ORDER BY at DESC LIMIT 1',
                   (claim_id,))
        rotation_id = rot['id'] if rot else None
    else:
        raise ValueError('rotation_id or claim_id required')
    targets = [dict(r) for r in db.execute(
        'SELECT * FROM kr_targets WHERE rotation_id=? ORDER BY kind,ref_id',
        (rotation_id,))] if rotation_id else []
    for t in targets:
        t['detail'] = _lj(t['detail'], {})
        if t['kind'] == 'snapshot':
            wrap = _one(
                db,
                'SELECT key_id,status FROM key_wraps WHERE claim_id=? AND snapshot_id=? LIMIT 1',
                (claim_id, t['ref_id']))
            t['has_wrap'] = wrap is not None
            t['wrap_key'] = wrap['key_id'] if wrap else None
    gaps = []
    for sid in _snapshot_ids(db, claim_id):
        if not _one(db, 'SELECT 1 FROM key_wraps WHERE claim_id=? AND snapshot_id=?',
                    (claim_id, sid)):
            gaps.append({'kind': 'missing_wrap', 'snapshot_id': sid})
    target_refs = {(t['kind'], t['ref_id']) for t in targets}
    for r in db.execute('SELECT id FROM kr_external WHERE claim_id=?', (claim_id,)):
        if ('external_wrap', r['id']) not in target_refs:
            gaps.append({'kind': 'external_not_in_rotation', 'external_id': r['id']})
    kinds = sorted({t['kind'] for t in targets})
    return {'rotation_id': rotation_id, 'claim_id': claim_id, 'kinds': kinds,
            'target_count': len(targets), 'targets': targets, 'gaps': gaps}


# ---------------------------------------------------------------------------
# key registry and rotation
# ---------------------------------------------------------------------------

def _op_register_key(db, p):
    key_id = g(p, 'key_id', 'key')
    claim_id = _derive_claim(db, p, key_id=key_id)
    if not key_id or not claim_id:
        return {'decision': 'blocked', 'reason': 'key_and_claim_required'}
    epoch = int(g(p, 'epoch', 'version', 'key_epoch', default=1))
    state = g(p, 'state', 'key_state', default='current')
    row = _key_row(db, key_id)
    if row:
        if row['claim_id'] != claim_id or row['epoch'] != epoch:
            return {'decision': 'conflict', 'reason': 'key_identity_conflict'}
        return {'decision': 'reused', 'key_id': key_id, 'state': row['state']}
    current = _current_key(db, claim_id)
    if state == 'current' and current is not None and current['key_id'] != key_id:
        if epoch <= (current['epoch'] or 0):
            return {'decision': 'blocked', 'reason': 'stale_key_epoch',
                    'current_key': current['key_id']}
        # newer epoch registered directly: demote the previous current
        db.execute("UPDATE kr_keys SET state='retiring' WHERE claim_id=? AND state='current'",
                   (claim_id,))
    db.execute(
        'INSERT INTO kr_keys(key_id,claim_id,epoch,state,replaces,created_at,'
        'deadline,hard_deadline,purposes,holders,compromise) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (key_id, claim_id, epoch, state, g(p, 'replaces'), _at(p),
         g(p, 'deadline'), g(p, 'hard_deadline'),
         _j(g(p, 'purposes', 'allowed_purposes',
              default=['unwrap', 'decrypt', 'rewrap'])),
         _j(g(p, 'holders', 'allowed_holders', 'sites', default=[])),
         1 if g(p, 'compromised', 'compromise', default=False) else 0))
    return {'decision': 'registered', 'key_id': key_id, 'claim_id': claim_id,
            'epoch': epoch, 'state': state}


def _op_rotate(db, p):
    rid = _id(p, 'rotation_id')
    claim_id = _derive_claim(db, p)
    from_key = g(p, 'from_key', 'old_key', 'from', 'old')
    to_key = g(p, 'to_key', 'new_key', 'to', 'new')
    at = _at(p)
    if not rid:
        return {'decision': 'blocked', 'reason': 'rotation_id_required'}
    if not claim_id or not from_key or not to_key:
        return {'decision': 'blocked', 'reason': 'rotation_identity_required'}
    old_rot = _one(db, 'SELECT * FROM kr_rotations WHERE id=?', (rid,))
    if old_rot:
        same = (old_rot['claim_id'] == claim_id
                and old_rot['from_key'] == from_key
                and old_rot['to_key'] == to_key)
        if not same:
            return {'decision': 'conflict', 'reason': 'rotation_conflict'}
        scope = rotation_scope(db, rotation_id=rid)
        return {'decision': 'reused', 'rotation_id': rid, 'scope': scope}

    # implicit registration of the outgoing key as the current epoch-1 key
    old = _key_row(db, from_key)
    if old is None:
        cur = _current_key(db, claim_id)
        if cur is not None and cur['key_id'] != from_key:
            return {'decision': 'blocked', 'reason': 'stale_key_epoch',
                    'current_key': cur['key_id']}
        db.execute(
            "INSERT INTO kr_keys(key_id,claim_id,epoch,state,created_at,purposes,holders) "
            "VALUES(?,?,1,'current',?,?,'[]')",
            (from_key, claim_id, at, _j(['unwrap', 'decrypt', 'rewrap'])))
        old = _key_row(db, from_key)

    current = _current_key(db, claim_id)
    if current is None or current['key_id'] != from_key:
        return {'decision': 'blocked', 'reason': 'stale_key_epoch',
                'current_key': current['key_id'] if current else None}

    new_epoch = int(g(p, 'to_epoch', 'new_epoch', 'epoch',
                      default=(old['epoch'] or 1) + 1))
    existing_to = _key_row(db, to_key)
    if existing_to is not None and existing_to['claim_id'] != claim_id:
        return {'decision': 'conflict', 'reason': 'key_identity_conflict'}

    ttl = g(p, 'ttl', 'window', 'legacy_ttl', default=DEFAULT_TTL)
    deadline = g(p, 'deadline', 'legacy_deadline')
    if deadline is None and at is not None:
        deadline = at + int(ttl)
    hard_deadline = g(p, 'hard_deadline', 'max_deadline')
    hard_ttl = g(p, 'hard_ttl', default=DEFAULT_HARD_TTL)
    if hard_deadline is None and at is not None:
        hard_deadline = at + int(hard_ttl)
    purposes = g(p, 'purposes', 'allowed_purposes', 'legacy_purposes',
                 default=['unwrap', 'rewrap'])
    holders = g(p, 'holders', 'allowed_holders', default=None)

    db.execute('INSERT INTO kr_rotations VALUES(?,?,?,?,?,?,?)',
               (rid, claim_id, from_key, to_key, at, 'started',
                _j({'deadline': deadline, 'hard_deadline': hard_deadline})))
    db.execute(
        "UPDATE kr_keys SET state='retiring', rotate_id=?, deadline=?, "
        "hard_deadline=?, purposes=?, holders=? WHERE key_id=?",
        (rid, deadline, hard_deadline, _j(purposes),
         _j(holders if holders is not None else []), from_key))
    if existing_to is None:
        db.execute(
            "INSERT INTO kr_keys(key_id,claim_id,epoch,state,replaces,"
            "created_at,rotate_id,purposes,holders) VALUES(?,?,?,'current',?,?,?,?,'[]')",
            (to_key, claim_id, new_epoch, from_key, at, rid,
             _j(['wrap', 'unwrap', 'decrypt', 'rewrap'])))
    else:
        if existing_to['epoch'] and new_epoch < existing_to['epoch']:
            return {'decision': 'blocked', 'reason': 'stale_key_epoch'}
        db.execute(
            "UPDATE kr_keys SET state='current', replaces=?, rotate_id=? WHERE key_id=?",
            (from_key, rid, to_key))
        db.execute(
            "UPDATE kr_keys SET state='retiring' WHERE claim_id=? AND key_id!=? "
            "AND state='current'", (claim_id, to_key))

    # default holders: every site that holds an envelope for this claim
    if holders is None:
        sites = sorted({r['site'] for r in db.execute(
            'SELECT DISTINCT site FROM key_wraps WHERE claim_id=? AND site IS NOT NULL',
            (claim_id,))})
        db.execute('UPDATE kr_keys SET holders=? WHERE key_id=?',
                   (_j(sites), from_key))

    # one bounded legacy window, broad to the claim but purpose/holder/time bound
    db.execute('INSERT INTO kr_windows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (f'legacy:{rid}', claim_id, from_key, 'legacy', None, None,
                _j(purposes), _j([]), at, deadline, 'active', None, None, None))

    _build_targets(db, p, rid, claim_id, from_key, to_key)
    scope = rotation_scope(db, rotation_id=rid)
    return {'decision': 'rotation_started', 'rotation_id': rid,
            'claim_id': claim_id, 'from_key': from_key, 'to_key': to_key,
            'epoch': new_epoch,
            'legacy': {'key_id': from_key, 'deadline': deadline,
                       'hard_deadline': hard_deadline, 'purposes': purposes,
                       'holders': _lj(_one(db, 'SELECT holders FROM kr_keys WHERE key_id=?',
                                           (from_key,))['holders'])},
            'scope': scope}


def _op_receipt(db, p):
    rid = _id(p, 'receipt_id')
    key_id = g(p, 'key_id', 'key')
    action = g(p, 'action', default='rotate')
    at = _at(p)
    site = g(p, 'site', default='key-service')
    result = g(p, 'result', 'outcome', default='done')
    if at is None:
        at = 0
    recorded = key_service.receipt(db, rid, key_id, action, at, site, result)
    stale = False
    if recorded.get('decision') == 'recorded':
        prev = _one(
            db,
            'SELECT MAX(at) AS m FROM key_receipts WHERE key_id=? AND site=? '
            'AND action=? AND id!=?', (key_id, site, action, rid))
        if prev and prev['m'] is not None and at < prev['m']:
            stale = True
    out = dict(recorded)
    out.update({'stale': stale, 'ordered': not stale, 'key_id': key_id,
                'at': at, 'site': site})
    return out


def _op_probe(db, p, force_outcome=None):
    pid = _id(p, 'probe_id')
    claim_id = _derive_claim(db, p)
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    key_id = g(p, 'key_id', 'key')
    site = g(p, 'site')
    at = _at(p)
    outcome = force_outcome or g(p, 'outcome', 'result', default='failed')
    if at is None:
        at = 0
    if not pid:
        pid = f'probe:{snapshot_id}:{site}:{at}:{outcome}'
    res = decrypt_probe.result(db, pid, claim_id, snapshot_id, key_id, site,
                               at, outcome)
    out = dict(res)
    out['probe_id'] = pid
    return out


# ---------------------------------------------------------------------------
# observations and failure classification
# ---------------------------------------------------------------------------

def _op_observe(db, p, kind=None):
    kind = kind or g(p, 'kind', 'observation', 'observation_type')
    if not kind:
        return {'decision': 'blocked', 'reason': 'observation_kind_required'}
    oid = _id(p, 'observation_id') or g(p, 'obs_id')
    claim_id = _derive_claim(db, p)
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    site = g(p, 'site')
    at = _at(p)
    if not oid:
        oid = f'obs:{kind}:{snapshot_id}:{site}:{at}'
    if _one(db, 'SELECT 1 FROM kr_obs WHERE id=?', (oid,)):
        return {'decision': 'reused', 'observation_id': oid}
    detail = {k: v for k, v in p.items()
              if k not in ('op', 'id', 'observation_id', 'obs_id')}
    db.execute('INSERT INTO kr_obs VALUES(?,?,?,?,?,?,?)',
               (oid, claim_id, snapshot_id, site, at, kind, _j(detail)))
    return {'decision': 'observed', 'observation_id': oid, 'kind': kind}


def _latest_obs(db, snapshot_id, kind, site=None):
    if site:
        row = _one(
            db,
            'SELECT * FROM kr_obs WHERE snapshot_id=? AND kind=? AND site=? '
            'ORDER BY at DESC, rowid DESC LIMIT 1',
            (snapshot_id, kind, site))
        if row:
            return row
    return _one(
        db,
        'SELECT * FROM kr_obs WHERE snapshot_id=? AND kind=? '
        'ORDER BY at DESC, rowid DESC LIMIT 1', (snapshot_id, kind))


def _fact(p, obs, *names):
    value = g(p, *names)
    if value is not None:
        return value
    if obs:
        detail = _lj(obs['detail'], {})
        return g(detail, *names)
    return None


def _op_classify(db, p):
    probe_id = g(p, 'probe_id', 'probe')
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    site = g(p, 'site')
    claim_id = _derive_claim(db, p, snapshot_id=snapshot_id)

    probe = None
    if probe_id:
        probe = _one(db, 'SELECT * FROM decrypt_probes WHERE id=?', (probe_id,))
        if probe:
            snapshot_id = snapshot_id or probe['snapshot_id']
            claim_id = claim_id or probe['claim_id']
            site = site or probe['site']
    if probe is None and snapshot_id:
        q = ('SELECT * FROM decrypt_probes WHERE snapshot_id=? '
             'AND outcome IN (\'failed\',\'failure\',\'error\') ')
        args = [snapshot_id]
        if site:
            q += 'AND site=? '
            args.append(site)
        q += 'ORDER BY at DESC, rowid DESC LIMIT 1'
        probe = _one(db, q, tuple(args))
        if probe and not probe_id:
            probe_id = probe['id']

    key_obs = _latest_obs(db, snapshot_id, 'key_store', site) if snapshot_id else None
    wrap_obs = _latest_obs(db, snapshot_id, 'wrap_inspection', site) if snapshot_id else None
    cipher_obs = _latest_obs(db, snapshot_id, 'ciphertext', site) if snapshot_id else None

    key_present = _fact(p, key_obs, 'key_present', 'present', 'has_key')
    store_returned = _fact(p, key_obs, 'returned', 'online', 'store_returned')
    wrap_status = _fact(p, wrap_obs, 'wrap_status', 'envelope_status', 'status')
    version_match = _fact(p, wrap_obs, 'version_match', 'version_ok', 'compatible')
    unwrap_ok = _fact(p, wrap_obs, 'unwrap_ok', 'unsealed', 'unwrap_succeeded')
    auth_ok = _fact(p, cipher_obs, 'auth_ok', 'authenticated')
    intact = _fact(p, cipher_obs, 'ciphertext_intact', 'intact', 'digest_match')
    independent = bool(_fact(p, cipher_obs, 'independent', 'independent_evidence'))

    basis = {'probe_id': probe_id, 'key_present': key_present,
             'store_returned': store_returned, 'wrap_status': wrap_status,
             'version_match': version_match, 'unwrap_ok': unwrap_ok,
             'auth_ok': auth_ok, 'ciphertext_intact': intact}

    # Strongest: the envelope/key yielded the data key but authenticated
    # decryption failed -> the ciphertext itself is wrong.
    if unwrap_ok is True and auth_ok is False:
        classification = CIPHERTEXT_CORRUPT
    elif wrap_status in ('version_mismatch', 'unsupported_version', 'epoch_mismatch') \
            or version_match is False:
        classification = WRAP_VERSION_MISMATCH
    elif wrap_status in ('invalid', 'malformed', 'corrupt_envelope', 'wrap_corrupt'):
        classification = WRAP_INVALID
    elif intact is False and (independent or key_present is True
                              or unwrap_ok is True):
        # independent digest/media read-back proof, or a working key path,
        # isolates the corruption to the ciphertext
        classification = CIPHERTEXT_CORRUPT
    elif auth_ok is False and (key_present is True or unwrap_ok is True):
        classification = CIPHERTEXT_CORRUPT
    elif key_present is False:
        classification = MISSING_KEY
    elif store_returned is False and key_present is None:
        # site store offline and has not returned: cannot prove absence yet
        classification = UNDETERMINED
    else:
        classification = UNDETERMINED

    aid = g(p, 'assessment_id', 'id')
    if not aid:
        n = db.execute('SELECT COUNT(*) FROM kr_assessments WHERE snapshot_id=?',
                       (snapshot_id,)).fetchone()[0]
        aid = f'assess:{snapshot_id or probe_id}:{n + 1}'
    if _one(db, 'SELECT 1 FROM kr_assessments WHERE id=?', (aid,)):
        return {'decision': 'reused', 'assessment_id': aid,
                'classification': _one(db, 'SELECT classification FROM kr_assessments WHERE id=?',
                                       (aid,))['classification']}
    at = _at(p)
    db.execute('INSERT INTO kr_assessments VALUES(?,?,?,?,?,?,?)',
               (aid, probe_id, snapshot_id, claim_id, at, classification,
                _j(basis)))
    if snapshot_id:
        _upsert_acceptance(db, snapshot_id, claim_id,
                           classification=classification)
    return {'decision': 'assessed', 'assessment_id': aid,
            'classification': classification, 'category': classification,
            'diagnosis': classification, 'verdict': classification,
            'code': classification, 'basis': basis,
            'probe_id': probe_id, 'snapshot_id': snapshot_id}


# ---------------------------------------------------------------------------
# read path and restore gate
# ---------------------------------------------------------------------------

def _window_covers(db, window, at, snapshot_id, purpose=None):
    if window['state'] != 'active':
        return False, f"window_{window['state']}"
    if at is not None and window['deadline'] is not None \
            and at > window['deadline']:
        return False, 'window_expired'
    refs = _lj(window['refs'])
    if refs and snapshot_id not in refs:
        return False, 'snapshot_scope_denied'
    if purpose:
        purposes = _lj(window['purposes'])
        if not _purpose_allows(purposes, purpose):
            return False, 'purpose_not_permitted'
    return True, None


def _purpose_allows(granted, requested):
    if requested in granted:
        return True
    # coarse unwrap/rewrap grants cover the combined escrow action
    aliases = {
        'rewrap': {'rewrap', 'unwrap_for_rewrap'},
        'unwrap': {'unwrap', 'unwrap_for_rewrap'},
        'decrypt': {'decrypt', 'read', 'unwrap'},
    }
    return bool(aliases.get(requested, set()) & set(granted))


def _read_path(db, claim_id, snapshot_id, at=None):
    """Return a qualifying decryption path for one snapshot, else reason."""
    current = _current_key(db, claim_id)
    current_id = current['key_id'] if current else None
    probes = db.execute(
        'SELECT * FROM decrypt_probes WHERE snapshot_id=? ORDER BY at DESC, rowid DESC',
        (snapshot_id,)).fetchall() if _table_exists(db, 'decrypt_probes') else []
    successes = [r for r in probes if r['outcome'] in SUCCESS_OUTCOMES]

    if current_id:
        for r in successes:
            if r['key_id'] == current_id:
                return {'allowed': True, 'via': 'current_readback',
                        'key_id': current_id, 'probe_id': r['id'],
                        'site': r['site'], 'at': r['at']}

    # bounded legacy / escrow windows can make an old-key read acceptable
    fallback_window = None
    for r in successes:
        wins = db.execute(
            "SELECT * FROM kr_windows WHERE key_id=? AND state='active'",
            (r['key_id'],)).fetchall()
        for w in wins:
            ok, why = _window_covers(db, w, at, snapshot_id)
            if not ok:
                continue
            path = {'allowed': True,
                    'via': 'escrow_window' if w['mode'] == 'escrow'
                    else 'legacy_window',
                    'window_id': w['id'], 'key_id': r['key_id'],
                    'probe_id': r['id'], 'site': r['site'], 'at': r['at']}
            if w['mode'] == 'escrow':
                return path  # most specific authorization wins
            fallback_window = fallback_window or path
    if fallback_window:
        return fallback_window

    if successes:
        return {'allowed': False, 'reason': 'readback_key_not_current',
                'last_success_key': successes[0]['key_id'],
                'current_key': current_id}
    failed = [r for r in probes if r['outcome'] in FAILURE_OUTCOMES]
    if failed:
        return {'allowed': False, 'reason': 'only_failed_probes',
                'last_failure_probe': failed[0]['id']}
    return {'allowed': False, 'reason': 'no_verified_readback',
            'current_key': current_id}


def _evaluate_snapshot(db, claim_id, snapshot_id, at=None):
    snap = _one(db, 'SELECT * FROM snapshots WHERE id=?', (snapshot_id,)) \
        if _table_exists(db, 'snapshots') else None
    acc = _one(db, 'SELECT * FROM kr_acceptance WHERE snapshot_id=?',
               (snapshot_id,))
    chain_valid = None
    if snap is not None:
        try:
            chain_valid = bool(recovery.valid_chain(db, snap, claim_id))
        except Exception:
            chain_valid = False

    path = _read_path(db, claim_id, snapshot_id, at)
    quarantined = bool(acc and acc['state'] == 'quarantined')
    reasons = []
    if chain_valid is False:
        reasons.append('broken_chain')
    if quarantined:
        reasons.append('snapshot_quarantined')
    if not path.get('allowed'):
        reasons.append(path.get('reason', 'no_verified_readback'))

    if quarantined:
        acceptance = 'quarantined'
    elif path.get('allowed'):
        acceptance = ('escrow_only' if path['via'] == 'escrow_window'
                      else 'legacy_readable' if path['via'] == 'legacy_window'
                      else 'readable')
    elif acc and acc['state'] in ('quarantined',):
        acceptance = 'quarantined'
    else:
        acceptance = 'unverified'

    classification = acc['classification'] if acc and acc['classification'] else None
    if not classification:
        a = _one(
            db,
            'SELECT classification FROM kr_assessments WHERE snapshot_id=? '
            'ORDER BY at DESC, rowid DESC LIMIT 1', (snapshot_id,))
        classification = a['classification'] if a else None

    wraps = [dict(r) for r in db.execute(
        'SELECT id,key_id,epoch,site,status FROM key_wraps WHERE claim_id=? AND snapshot_id=?',
        (claim_id, snapshot_id))] if _table_exists(db, 'key_wraps') else []
    latest_probe = _one(
        db,
        'SELECT id,key_id,site,at,outcome FROM decrypt_probes WHERE snapshot_id=? '
        'ORDER BY at DESC, rowid DESC LIMIT 1', (snapshot_id,)) \
        if _table_exists(db, 'decrypt_probes') else None
    return {'snapshot_id': snapshot_id,
            'site': wraps[0]['site'] if wraps else None,
            'generation': snap['generation'] if snap else None,
            'parent': snap['parent'] if snap else None,
            'chain_valid': chain_valid,
            'acceptance': acceptance, 'quarantined': quarantined,
            'classification': classification, 'allowed': not reasons,
            'blocking_reasons': reasons, 'readback': path if path.get('allowed') else None,
            'read_path': path, 'wraps': wraps,
            'latest_probe': dict(latest_probe) if latest_probe else None}


def gate_restore(db, claim_id, snapshot_id, at=None, include_ancestors=True):
    """Acceptance-aware restore gate: chain validity AND a real read path."""
    ensure(db)
    claim_id = claim_id or _derive_claim(db, {}, snapshot_id=snapshot_id)
    target = _evaluate_snapshot(db, claim_id, snapshot_id, at)
    chain = [target]
    reasons = list(target['blocking_reasons'])
    if include_ancestors and _table_exists(db, 'snapshots'):
        current = _one(db, 'SELECT * FROM snapshots WHERE id=?', (snapshot_id,))
        seen = set()
        while current and current['parent']:
            pid = current['parent']
            if pid in seen:
                reasons.append('broken_chain')
                break
            seen.add(pid)
            parent = _evaluate_snapshot(db, claim_id, pid, at)
            chain.append(parent)
            for r in parent['blocking_reasons']:
                if r not in reasons:
                    reasons.append(r)
            current = _one(db, 'SELECT * FROM snapshots WHERE id=?', (pid,))
    return {'allowed': not reasons, 'decision': 'allowed' if not reasons else 'blocked',
            'claim_id': claim_id, 'snapshot_id': snapshot_id,
            'reasons': reasons, 'reason': reasons[0] if reasons else None,
            'chain': chain}


def _op_quarantine(db, p):
    eid = _id(p, 'event_id')
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    if not snapshot_id:
        return {'decision': 'blocked', 'reason': 'snapshot_required'}
    if eid and _one(db, 'SELECT 1 FROM kr_events WHERE id=?', (eid,)):
        return {'decision': 'reused', 'event_id': eid}
    claim_id = _derive_claim(db, p, snapshot_id=snapshot_id)
    at = _at(p)
    reason = g(p, 'reason', 'classification',
               default='unresolved_decrypt_failure')
    _upsert_acceptance(db, snapshot_id, claim_id, state='quarantined',
                       reason=reason, since=at,
                       classification=g(p, 'classification'))
    event_id = _add_event(db, eid, claim_id, snapshot_id, at, 'quarantined',
                          {'reason': reason, 'by': g(p, 'by', 'actor')})
    q = [r['snapshot_id'] for r in db.execute(
        "SELECT snapshot_id FROM kr_acceptance WHERE claim_id=? AND state='quarantined'",
        (claim_id,))]
    return {'decision': 'quarantined', 'event_id': event_id,
            'snapshot_id': snapshot_id, 'reason': reason,
            'quarantined': q}


def _op_readback(db, p):
    out = _op_probe(db, p, force_outcome='success')
    if out.get('decision') in ('conflict', 'invalid'):
        return {'decision': out['decision'],
                'reason': 'probe_immutable_conflict' if out['decision'] == 'conflict'
                else 'invalid_probe', 'probe': out}
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    claim_id = _derive_claim(db, p, snapshot_id=snapshot_id)
    at = _at(p)
    path = _read_path(db, claim_id, snapshot_id, at)
    accepted = bool(path.get('allowed'))
    acc = _one(db, 'SELECT state FROM kr_acceptance WHERE snapshot_id=?',
               (snapshot_id,))
    quarantined = bool(acc and acc['state'] == 'quarantined')
    if accepted:
        if quarantined:
            # evidence is recorded but only the explicit release op, with its
            # current-wrap check, may lift the quarantine
            _upsert_acceptance(db, snapshot_id, claim_id,
                               key_id=path['key_id'],
                               readback_probe=path['probe_id'],
                               readback_at=path['at'],
                               site=path.get('site'))
            _add_event(db, _id(p, 'event_id'), claim_id, snapshot_id, at,
                       'readback_verified_pending_release', path)
            return {'decision': 'readback_verified', 'accepted': True,
                    'release_required': True, 'quarantined': True,
                    'snapshot_id': snapshot_id, 'path': path,
                    'probe_decision': out.get('decision')}
        _upsert_acceptance(db, snapshot_id, claim_id,
                           state=('escrow_only' if path['via'] == 'escrow_window'
                                  else 'readable'),
                           key_id=path['key_id'],
                           readback_probe=path['probe_id'],
                           readback_at=path['at'],
                           site=path.get('site'), window_id=path.get('window_id'))
        _add_event(db, _id(p, 'event_id'), claim_id, snapshot_id, at,
                   'readback_verified', path)
        return {'decision': 'readback_verified', 'accepted': True,
                'snapshot_id': snapshot_id, 'path': path,
                'probe_decision': out.get('decision')}
    return {'decision': 'readback_recorded_not_accepted', 'accepted': False,
            'snapshot_id': snapshot_id, 'path': path,
            'reason': path.get('reason'), 'probe_decision': out.get('decision')}


def _op_rewrap(db, p):
    wid = g(p, 'wrap_id', 'id', 'new_wrap_id')
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    claim_id = _derive_claim(db, p, snapshot_id=snapshot_id)
    to_key = g(p, 'to_key', 'new_key')
    if not wid or not snapshot_id or not to_key or not claim_id:
        return {'decision': 'blocked',
                'reason': 'wrap_snapshot_target_key_required'}
    at = _at(p)
    site = g(p, 'site')
    epoch = g(p, 'epoch')
    if epoch is None:
        k = _key_row(db, to_key)
        epoch = k['epoch'] if k else 1

    window_id = g(p, 'window_id', 'case_id', 'escrow_case')
    if window_id:
        w = _one(db, 'SELECT * FROM kr_windows WHERE id=?', (window_id,))
        if not w:
            return {'decision': 'blocked', 'reason': 'unknown_window'}
        ok, why = _window_covers(db, w, at, snapshot_id, purpose='rewrap')
        if not ok:
            return {'decision': 'blocked', 'reason': why}
        if w['mode'] == 'escrow' and not w['access_proof']:
            return {'decision': 'blocked',
                    'reason': 'escrow_access_proof_required'}
    else:
        acc = _one(db, 'SELECT state FROM kr_acceptance WHERE snapshot_id=?',
                   (snapshot_id,))
        if not acc or acc['state'] != 'quarantined':
            return {'decision': 'blocked',
                    'reason': 'rewrap_requires_quarantine_or_window'}
        source_wrap = g(p, 'source_wrap', 'independent_wrap')
        if source_wrap:
            sw = _one(db, 'SELECT 1 FROM key_wraps WHERE id=?', (source_wrap,))
            if not sw:
                return {'decision': 'blocked', 'reason': 'unknown_source_wrap'}
        elif site:
            sw = _one(db,
                      'SELECT 1 FROM key_wraps WHERE claim_id=? AND snapshot_id=? AND site=?',
                      (claim_id, snapshot_id, site))
            if not sw:
                return {'decision': 'blocked',
                        'reason': 'independent_wrap_required'}
        intact = g(p, 'ciphertext_intact', 'intact')
        if intact is None:
            obs = _latest_obs(db, snapshot_id, 'ciphertext', site)
            if obs:
                intact = _fact(p, obs, 'ciphertext_intact', 'intact',
                               'digest_match')
        if intact is not True:
            return {'decision': 'blocked',
                    'reason': 'ciphertext_readback_required'}

    res = key_wrap.record(db, wid, to_key, claim_id, snapshot_id,
                          int(epoch), site, g(p, 'status', default='rewrapped'))
    if res.get('decision') == 'conflict':
        return {'decision': 'conflict', 'reason': 'wrap_conflict', 'wrap': res}
    _add_event(db, g(p, 'event_id'), claim_id, snapshot_id, at, 'rewrapped',
               {'wrap_id': wid, 'to_key': to_key,
                'from_key': g(p, 'from_key', 'old_key'),
                'window_id': window_id})
    _upsert_acceptance(db, snapshot_id, claim_id, key_id=to_key)
    return {'decision': 'rewrapped', 'wrap_id': wid,
            'snapshot_id': snapshot_id, 'to_key': to_key,
            'record_decision': res.get('decision')}


def _op_release(db, p):
    eid = _id(p, 'event_id')
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    claim_id = _derive_claim(db, p, snapshot_id=snapshot_id)
    at = _at(p)
    if eid and _one(db, 'SELECT 1 FROM kr_events WHERE id=?', (eid,)):
        return {'decision': 'reused', 'event_id': eid}
    acc = _one(db, 'SELECT * FROM kr_acceptance WHERE snapshot_id=?',
               (snapshot_id,))
    if not acc or acc['state'] != 'quarantined':
        return {'decision': 'blocked', 'reason': 'not_quarantined'}
    path = _read_path(db, claim_id, snapshot_id, at)
    if not path.get('allowed'):
        return {'decision': 'blocked',
                'reason': path.get('reason', 'readback_required'),
                'reasons': [path.get('reason', 'readback_required')],
                'path': path}
    current_id = _current_key_id(db, claim_id)
    if current_id and not _one(
            db,
            'SELECT 1 FROM key_wraps WHERE claim_id=? AND snapshot_id=? AND key_id=?',
            (claim_id, snapshot_id, current_id)):
        return {'decision': 'blocked', 'reason': 'current_wrap_required'}
    _upsert_acceptance(db, snapshot_id, claim_id, state='readable',
                       key_id=path['key_id'], readback_probe=path['probe_id'],
                       readback_at=path['at'], window_id=None, reason=None)
    event_id = _add_event(db, eid, claim_id, snapshot_id, at, 'quarantine_released',
                          {'path': path})
    return {'decision': 'released', 'event_id': event_id,
            'snapshot_id': snapshot_id, 'state': 'readable', 'path': path}


# ---------------------------------------------------------------------------
# late offline wraps, external copies, compromise and bounded key use
# ---------------------------------------------------------------------------

def _op_offline_wraps(db, p):
    batch_id = _id(p, 'batch_id') or g(p, 'import_id')
    claim_id = _derive_claim(db, p)
    site = g(p, 'site', default='offline-store')
    at = _at(p)
    wraps = g(p, 'wraps', 'items', 'records', default=[]) or []
    if not batch_id:
        batch_id = f'offline:{claim_id}:{site}:{at}'
    if _one(db, 'SELECT 1 FROM kr_obs WHERE id=?', (batch_id,)):
        return {'decision': 'reused', 'batch_id': batch_id}
    results = []
    recorded = 0
    for i, w in enumerate(wraps):
        wid = g(w, 'wrap_id', 'id') or f'{batch_id}:wrap:{i}'
        key_id = g(w, 'key_id', 'key')
        sid = g(w, 'snapshot_id', 'snapshot')
        wclaim = g(w, 'claim_id', 'claim', default=claim_id)
        epoch = int(g(w, 'epoch', default=1))
        wsite = g(w, 'site', default=site)
        status = g(w, 'status', default='offline_reported')
        res = key_wrap.record(db, wid, key_id, wclaim, sid, epoch, wsite, status)
        results.append({'wrap_id': wid, 'decision': res.get('decision')})
        if res.get('decision') == 'recorded':
            recorded += 1
        # append the late envelope to every active rotation's scope
        for rot in db.execute(
                "SELECT id FROM kr_rotations WHERE claim_id=? AND state='started'",
                (wclaim,)):
            tid = f"{rot['id']}:snapshot:{sid}" + (f'@{wsite}' if wsite else '')
            if not _one(db, 'SELECT 1 FROM kr_targets WHERE id=?', (tid,)):
                db.execute('INSERT OR IGNORE INTO kr_targets VALUES(?,?,?,?,?,?,?,?,?)',
                           (tid, rot['id'], wclaim, 'snapshot', str(sid), wsite,
                            wid, 'in_scope', _j({'late': True, 'key_id': key_id})))
    db.execute('INSERT INTO kr_obs VALUES(?,?,?,?,?,?,?)',
               (batch_id, claim_id, None, site, at, 'offline_store',
                _j({'returned': True, 'wrap_count': len(wraps),
                    'recorded': recorded})))
    _add_event(db, None, claim_id, None, at, 'offline_wraps_imported',
               {'batch_id': batch_id, 'count': len(wraps)})
    return {'decision': 'imported', 'batch_id': batch_id,
            'recorded': recorded, 'wrap_count': len(wraps), 'items': results}


def _op_external_copy(db, p):
    cid = _id(p, 'copy_id', 'location_id')
    key_id = g(p, 'key_id', 'key')
    claim_id = _derive_claim(db, p, key_id=key_id)
    if not cid or not key_id:
        return {'decision': 'blocked', 'reason': 'external_copy_identity_required'}
    at = _at(p)
    if _one(db, 'SELECT 1 FROM kr_external WHERE id=?', (cid,)):
        return {'decision': 'reused', 'copy_id': cid}
    db.execute('INSERT INTO kr_external VALUES(?,?,?,?,?,?,?,?,?)',
               (cid, key_id, claim_id, g(p, 'location', default=cid),
                g(p, 'holder'), g(p, 'site'), at,
                g(p, 'disposition', default='open'), g(p, 'proof')))
    return {'decision': 'registered', 'copy_id': cid, 'key_id': key_id,
            'disposition': 'open'}


def _op_attest_external(db, p):
    cid = _id(p, 'copy_id', 'location_id')
    row = _one(db, 'SELECT * FROM kr_external WHERE id=?', (cid,))
    if not row:
        return {'decision': 'blocked', 'reason': 'unknown_external_copy'}
    disposition = g(p, 'disposition', 'state',
                    default='secured')
    if disposition not in ('rewrapped', 'destroyed', 'secured', 'returned'):
        return {'decision': 'blocked', 'reason': 'invalid_disposition'}
    proof = g(p, 'proof', 'attestation')
    if not proof and disposition in ('destroyed', 'rewrapped'):
        return {'decision': 'blocked', 'reason': 'attestation_proof_required'}
    db.execute('UPDATE kr_external SET disposition=?, proof=? WHERE id=?',
               (disposition, proof, cid))
    return {'decision': 'attested', 'copy_id': cid, 'disposition': disposition}


def _op_compromise(db, p):
    key_id = g(p, 'key_id', 'key')
    row = _key_row(db, key_id)
    if not row:
        return {'decision': 'blocked', 'reason': 'unknown_key'}
    at = _at(p)
    proof = g(p, 'proof', 'evidence_id', 'source')
    db.execute('UPDATE kr_keys SET compromise=1, compromise_at=? WHERE key_id=?',
               (at, key_id))
    _add_event(db, _id(p, 'event_id'), row['claim_id'], None, at,
               'compromise_confirmed', {'key_id': key_id, 'proof': proof})
    return {'decision': 'compromise_confirmed', 'key_id': key_id,
            'renewal': 'denied'}


def _op_renew(db, p):
    key_id = g(p, 'key_id', 'key')
    row = _key_row(db, key_id)
    if not row:
        return {'decision': 'blocked', 'reason': 'unknown_key'}
    if row['state'] != 'retiring':
        return {'decision': 'blocked', 'reason': 'key_not_in_coexistence',
                'state': row['state']}
    if row['compromise']:
        _add_event(db, _id(p, 'event_id'), row['claim_id'], None, _at(p),
                   'renewal_denied',
                   {'key_id': key_id, 'reason': 'compromised_key_renewal_denied',
                    'request_reason': g(p, 'reason')})
        return {'decision': 'denied',
                'reason': 'compromised_key_renewal_denied',
                'key_id': key_id}
    new_deadline = g(p, 'new_deadline', 'deadline', 'until')
    at = _at(p)
    ttl = g(p, 'ttl', 'extend')
    if new_deadline is None and ttl is not None and at is not None:
        new_deadline = at + int(ttl)
    if new_deadline is None:
        return {'decision': 'blocked', 'reason': 'new_deadline_required'}
    hard = row['hard_deadline']
    if hard is not None and new_deadline > hard:
        return {'decision': 'denied', 'reason': 'renewal_beyond_hard_deadline',
                'hard_deadline': hard, 'requested_deadline': new_deadline}
    if row['deadline'] is not None and new_deadline <= row['deadline']:
        return {'decision': 'unchanged', 'deadline': row['deadline']}
    db.execute('UPDATE kr_keys SET deadline=? WHERE key_id=?',
               (new_deadline, key_id))
    db.execute("UPDATE kr_windows SET deadline=? WHERE key_id=? AND mode='legacy' AND state='active'",
               (new_deadline, key_id))
    _add_event(db, _id(p, 'event_id'), row['claim_id'], None, at,
               'legacy_renewed', {'key_id': key_id, 'deadline': new_deadline,
                                  'reason': g(p, 'reason'),
                                  'holder': g(p, 'holder')})
    return {'decision': 'renewed', 'key_id': key_id,
            'deadline': new_deadline, 'hard_deadline': hard}


def _op_access(db, p):
    aid = _id(p, 'access_id') or _id(p)
    key_id = g(p, 'key_id', 'key')
    holder = g(p, 'holder', 'actor', 'principal')
    purpose = g(p, 'purpose', default='unwrap')
    ref_id = g(p, 'ref_id', 'snapshot_id', 'snapshot')
    at = _at(p)
    proof = g(p, 'proof')
    claim_id = _derive_claim(db, p, snapshot_id=ref_id, key_id=key_id)
    if not aid:
        aid = _next_seq_id(db, 'kr_access_events', 'id', 'access')
    if _one(db, 'SELECT 1 FROM kr_access_events WHERE id=?', (aid,)):
        return {'decision': 'reused', 'access_id': aid}

    def deny(reason):
        db.execute('INSERT INTO kr_access_events VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   (aid, g(p, 'window_id', 'case_id'), key_id, claim_id, holder,
                    purpose, ref_id, at, proof, 'denied', reason))
        return {'decision': 'denied', 'reason': reason, 'access_id': aid}

    k = _key_row(db, key_id)
    if not k:
        return deny('unknown_key')
    if k['state'] in ('revoked', 'destroyed'):
        return deny(f"key_{k['state']}")
    if at is not None and k['deadline'] is not None and at > k['deadline']:
        return deny('legacy_window_expired')
    allowed_holders = _lj(k['holders'])
    window_id = g(p, 'window_id', 'case_id')
    w = _one(db, 'SELECT * FROM kr_windows WHERE id=?', (window_id,)) if window_id else None
    if w is not None:
        ok, why = _window_covers(db, w, at, ref_id, purpose)
        if not ok:
            return deny(why)
        # a window-specific custodian narrows the grant; otherwise the key's
        # holder list still applies (empty list authorizes nobody)
        effective_holders = [w['holder']] if w['holder'] else allowed_holders
        if not holder or not effective_holders or holder not in effective_holders:
            return deny('holder_not_authorized')
    else:
        if not holder or not allowed_holders or holder not in allowed_holders:
            return deny('holder_not_authorized')
        purposes = _lj(k['purposes'])
        if purposes and not _purpose_allows(purposes, purpose):
            return deny('purpose_not_permitted')
    db.execute('INSERT INTO kr_access_events VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (aid, window_id, key_id, claim_id, holder, purpose, ref_id, at,
                proof, 'allowed', None))
    return {'decision': 'allowed', 'access_id': aid, 'key_id': key_id,
            'holder': holder, 'purpose': purpose, 'ref_id': ref_id}


# ---------------------------------------------------------------------------
# escrow
# ---------------------------------------------------------------------------

def _op_register_escrow(db, p):
    eid = _id(p, 'env_id', 'escrow_id')
    site = g(p, 'site')
    holder = g(p, 'holder', 'custodian')
    verified = bool(g(p, 'verified', default=False))
    proof = g(p, 'proof', 'verification_proof')
    at = _at(p)
    if not eid:
        return {'decision': 'blocked', 'reason': 'escrow_id_required'}
    if verified and not proof:
        return {'decision': 'blocked',
                'reason': 'environment_verification_proof_required'}
    if _one(db, 'SELECT 1 FROM kr_escrow_envs WHERE id=?', (eid,)):
        return {'decision': 'reused', 'env_id': eid}
    db.execute('INSERT INTO kr_escrow_envs VALUES(?,?,?,?,?,?,?,?)',
               (eid, site, holder, 1 if verified else 0, proof, at,
                'unknown', None))
    return {'decision': 'registered', 'env_id': eid, 'verified': verified}


def _op_escrow_contact(db, p):
    eid = g(p, 'env_id', 'escrow_id')
    env = _one(db, 'SELECT * FROM kr_escrow_envs WHERE id=?', (eid,))
    if not env:
        return {'decision': 'blocked', 'reason': 'unknown_escrow_environment'}
    reachable = g(p, 'reachable', 'online', default=None)
    if reachable is None:
        return {'decision': 'blocked', 'reason': 'reachability_required'}
    at = _at(p)
    proof = g(p, 'proof', 'contact_proof')
    state = 'reachable' if reachable else 'unreachable'
    db.execute('UPDATE kr_escrow_envs SET contact_state=?, contact_at=? WHERE id=?',
               (state, at, eid))
    db.execute('INSERT INTO kr_obs(id,claim_id,snapshot_id,site,at,kind,detail) '
               'VALUES(?,?,?,?,?,?,?)',
               (g(p, 'observation_id') or f'contact:{eid}:{at}', None, None,
                env['site'], at, 'escrow_contact',
                _j({'reachable': bool(reachable), 'proof': proof})))
    return {'decision': 'contact_recorded', 'env_id': eid,
            'reachable': bool(reachable)}


def _op_open_escrow(db, p):
    cid = _id(p, 'case_id')
    eid = g(p, 'env_id', 'escrow_id', 'environment')
    key_id = g(p, 'key_id', 'key')
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    snapshots = g(p, 'snapshots', 'refs', default=None)
    if snapshots is None:
        snapshots = [snapshot_id] if snapshot_id else []
    claim_id = _derive_claim(db, p, snapshot_id=snapshots[0] if snapshots else None,
                             key_id=key_id)
    at = _at(p)
    if not cid or not eid or not key_id or not snapshots:
        return {'decision': 'blocked', 'reason': 'escrow_case_identity_required'}
    if _one(db, 'SELECT 1 FROM kr_windows WHERE id=?', (cid,)):
        return {'decision': 'reused', 'case_id': cid}
    env = _one(db, 'SELECT * FROM kr_escrow_envs WHERE id=?', (eid,))
    if not env or not env['verified']:
        return {'decision': 'blocked',
                'reason': 'escrow_environment_unverified'}

    reachable = g(p, 'reachable')
    contact_proof = g(p, 'contact_proof')
    if reachable is False:
        return {'decision': 'blocked', 'reason': 'escrow_holder_unreachable'}
    if env['contact_state'] == 'unreachable' and reachable is not True:
        return {'decision': 'blocked', 'reason': 'escrow_holder_unreachable'}
    if env['contact_state'] != 'reachable':
        if reachable is not True:
            return {'decision': 'blocked', 'reason': 'escrow_contact_required'}
        if not contact_proof:
            return {'decision': 'blocked', 'reason': 'contact_proof_required'}
        db.execute('UPDATE kr_escrow_envs SET contact_state=\'reachable\', contact_at=? WHERE id=?',
                   (at, eid))

    deadline = g(p, 'deadline')
    ttl = g(p, 'ttl', 'window_minutes', default=DEFAULT_ESCROW_WINDOW)
    if deadline is None and at is not None:
        deadline = at + int(ttl)
    max_window = g(p, 'max_window', default=MAX_ESCROW_WINDOW)
    if at is not None and deadline is not None:
        if deadline <= at:
            return {'decision': 'blocked', 'reason': 'invalid_escrow_deadline'}
        if deadline - at > int(max_window):
            return {'decision': 'blocked', 'reason': 'escrow_window_too_long',
                    'max_window': max_window}
    purposes = g(p, 'purposes', default=['unwrap', 'rewrap'])
    db.execute('INSERT INTO kr_windows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (cid, claim_id, key_id, 'escrow',
                g(p, 'holder', default=env['holder']), env['site'],
                _j(purposes), _j(snapshots), at, deadline, 'active', eid,
                None, None))
    for sid in snapshots:
        _upsert_acceptance(db, sid, claim_id, state='escrow_only',
                           window_id=cid)
    _add_event(db, g(p, 'event_id'), claim_id, snapshots[0], at,
               'escrow_opened', {'case_id': cid, 'refs': snapshots,
                                 'deadline': deadline})
    return {'decision': 'escrow_opened', 'case_id': cid,
            'snapshots': snapshots, 'deadline': deadline,
            'holder': g(p, 'holder', default=env['holder'])}


def _op_escrow_access(db, p):
    cid = g(p, 'case_id', 'window_id')
    w = _one(db, 'SELECT * FROM kr_windows WHERE id=? AND mode=\'escrow\'', (cid,))
    if not w:
        return {'decision': 'blocked', 'reason': 'unknown_escrow_case'}
    proof = g(p, 'proof', 'access_proof', 'contact_proof_id')
    if not proof:
        return {'decision': 'blocked', 'reason': 'access_proof_required'}
    at = _at(p)
    holder = g(p, 'holder', default=w['holder'])
    ref_id = g(p, 'snapshot_id', 'snapshot',
               default=(_lj(w['refs'])[0] if _lj(w['refs']) else None))
    access = _op_access(db, {
        'id': g(p, 'access_id'), 'window_id': cid, 'key_id': w['key_id'],
        'holder': holder, 'purpose': g(p, 'purpose', default='unwrap'),
        'ref_id': ref_id, 'at': at, 'proof': proof})
    if access['decision'] != 'allowed':
        return access
    db.execute('UPDATE kr_windows SET access_proof=?, accessed_at=? WHERE id=?',
               (proof, at, cid))
    _add_event(db, g(p, 'event_id'), w['claim_id'], ref_id, at,
               'escrow_access_proven',
               {'case_id': cid, 'holder': holder, 'proof': proof})
    return {'decision': 'escrow_access_recorded', 'case_id': cid,
            'holder': holder, 'snapshot_id': ref_id, 'proof': proof,
            'access_id': access['access_id']}


def _revocation_blockers(db, key_row, at):
    claim_id = key_row['claim_id']
    snapshots = _snapshot_ids(db, claim_id)
    outstanding = []
    for sid in snapshots:
        acc = _one(db, 'SELECT state FROM kr_acceptance WHERE snapshot_id=?', (sid,))
        if acc and acc['state'] == 'quarantined':
            continue  # explicitly removed from the promised set
        verdict = gate_restore(db, claim_id, sid, at)
        if not verdict['allowed']:
            outstanding.append({'snapshot_id': sid,
                                'reasons': verdict['reasons']})
    external = [r['id'] for r in db.execute(
        "SELECT id FROM kr_external WHERE key_id=? AND disposition='open'",
        (key_row['key_id'],))]
    return outstanding, external


def revocation_readiness(db, key_id, at=None):
    """Explain exactly when an old key may be revoked.

    Revocation is allowed once every *promised* (non-quarantined) snapshot has
    a real read path, every external copy is attested, and any failed
    revocation receipt has been superseded by a successful retry.  Quarantined
    snapshots leave the promise set via an explicit decision, which is what
    lets an uncertain old key be retired on its bounded schedule.
    """
    ensure(db)
    k = _key_row(db, key_id)
    if not k:
        return {'decision': 'blocked', 'reason': 'unknown_key',
                'may_revoke': False, 'key_id': key_id}
    if k['state'] in ('revoked', 'destroyed'):
        return {'decision': k['state'], 'may_revoke': True,
                'key_id': key_id, 'state': k['state']}
    outstanding, external = _revocation_blockers(db, k, at)
    may = not outstanding and not external
    reasons = []
    if outstanding:
        reasons.append('outstanding_snapshot_readback')
    if external:
        reasons.append('external_copy_unsecured')
    return {'decision': 'ready' if may else 'blocked',
            'may_revoke': may, 'key_id': key_id, 'at': at,
            'state': k['state'], 'deadline': k['deadline'],
            'hard_deadline': k['hard_deadline'],
            'compromised': bool(k['compromise']),
            'outstanding_snapshots': outstanding,
            'external_copies': external, 'reasons': reasons}


def _op_revocation_readiness(db, p):
    return revocation_readiness(db, g(p, 'key_id', 'key'), _at(p))


def _op_revoke(db, p):
    rid = g(p, 'receipt_id', 'revocation_id') or _id(p)
    key_id = g(p, 'key_id', 'key')
    at = _at(p)
    if at is None:
        at = 0
    site = g(p, 'site', default='key-service')
    if not key_id:
        return {'decision': 'blocked', 'reason': 'key_required'}
    if not rid:
        rid = f'revoke:{key_id}:{at}'
    prior = _one(db, 'SELECT * FROM kr_revocations WHERE receipt_id=?', (rid,))
    requested_failed = (g(p, 'succeed', 'success') is False
                        or g(p, 'result', 'outcome') in FAILURE_OUTCOMES
                        or g(p, 'failure', 'fail', default=False) is True)
    if prior:
        wanted = 'failed' if requested_failed else 'revoked'
        if prior['result'] == wanted:
            return {'decision': 'reused', 'receipt_id': rid,
                    'result': prior['result']}
        return {'decision': 'conflict', 'reason': 'receipt_conflict'}
    k = _key_row(db, key_id)
    if not k:
        return {'decision': 'blocked', 'reason': 'unknown_key'}

    if requested_failed:
        key_service.receipt(db, rid, key_id, 'revoke', at, site, 'failed')
        db.execute('INSERT INTO kr_revocations VALUES(?,?,?,?,?,?)',
                   (rid, key_id, at, site, 'failed',
                    _j({'simulated': True})))
        db.execute("UPDATE kr_keys SET revoke_status='failed' WHERE key_id=?",
                   (key_id,))
        _add_event(db, g(p, 'event_id'), k['claim_id'], None, at,
                   'revocation_failed', {'key_id': key_id, 'receipt_id': rid})
        return {'decision': 'revocation_failed', 'receipt_id': rid,
                'key_id': key_id, 'reason': 'key_service_reported_failure'}

    outstanding, external = _revocation_blockers(db, k, at)
    if external:
        return {'decision': 'blocked', 'reason': 'external_copy_unsecured',
                'external_copies': external,
                'outstanding_snapshots': outstanding}
    if outstanding:
        return {'decision': 'blocked',
                'reason': 'outstanding_snapshot_readback',
                'snapshots': [o['snapshot_id'] for o in outstanding],
                'outstanding': outstanding}

    rec = key_service.receipt(db, rid, key_id, 'revoke', at, site, 'done')
    if rec.get('decision') == 'conflict':
        return {'decision': 'conflict', 'reason': 'service_receipt_conflict'}
    db.execute('INSERT INTO kr_revocations VALUES(?,?,?,?,?,?)',
               (rid, key_id, at, site, 'revoked', None))
    db.execute(
        "UPDATE kr_keys SET state='revoked', revoke_status='revoked', "
        "revoke_at=?, revoke_receipt=? WHERE key_id=?", (at, rid, key_id))
    db.execute("UPDATE kr_windows SET state='closed' WHERE key_id=? AND state='active'",
               (key_id,))
    _add_event(db, g(p, 'event_id'), k['claim_id'], None, at, 'key_revoked',
               {'key_id': key_id, 'receipt_id': rid})
    return {'decision': 'revoked', 'receipt_id': rid, 'key_id': key_id,
            'at': at}


def _op_destroy(db, p):
    key_id = g(p, 'key_id', 'key')
    proof = g(p, 'proof', 'destruction_proof')
    at = _at(p)
    k = _key_row(db, key_id)
    if not k:
        return {'decision': 'blocked', 'reason': 'unknown_key'}
    if not proof:
        return {'decision': 'blocked', 'reason': 'destruction_proof_required'}
    if k['state'] not in ('revoked', 'destroyed'):
        outstanding, external = _revocation_blockers(db, k, at or 0)
        if external:
            return {'decision': 'blocked', 'reason': 'external_copy_unsecured',
                    'external_copies': external}
        if outstanding:
            return {'decision': 'blocked',
                    'reason': 'outstanding_snapshot_readback',
                    'snapshots': [o['snapshot_id'] for o in outstanding]}
    rid = g(p, 'receipt_id') or f'destroy:{key_id}:{proof}'
    key_service.receipt(db, rid, key_id, 'destroy', at or 0,
                        g(p, 'site', default='key-service'), 'proven')
    db.execute(
        "UPDATE kr_keys SET state='destroyed', destroyed_at=?, "
        "destruction_proof=?, revoke_status=COALESCE(revoke_status,'revoked') "
        "WHERE key_id=?", (at, proof, key_id))
    _add_event(db, g(p, 'event_id'), k['claim_id'], None, at, 'key_destroyed',
               {'key_id': key_id, 'proof': proof})
    return {'decision': 'destroyed', 'key_id': key_id,
            'destruction_proof': proof}


# ---------------------------------------------------------------------------
# reports and histories
# ---------------------------------------------------------------------------

def recovery_report(db, claim_id, at=None):
    """Compute the current recovery-capability document (not persisted)."""
    ensure(db)
    claim_id = claim_id or g({}, 'claim_id')
    current = _current_key(db, claim_id)
    current_id = current['key_id'] if current else None
    snapshot_ids = _snapshot_ids(db, claim_id)
    snapshots = [_evaluate_snapshot(db, claim_id, sid, at) for sid in snapshot_ids]
    quarantined = [s['snapshot_id'] for s in snapshots if s['quarantined']]
    promised = [s['snapshot_id'] for s in snapshots if not s['quarantined']]
    incomplete = [s['snapshot_id'] for s in snapshots
                  if not s['quarantined'] and not s['allowed']]
    restricted = [s['snapshot_id'] for s in snapshots
                  if s.get('readback') and s['readback']['via']
                  in ('escrow_window', 'legacy_window')]

    keys = []
    for r in db.execute('SELECT * FROM kr_keys WHERE claim_id=? ORDER BY epoch',
                        (claim_id,)):
        d = dict(r)
        d['purposes'] = _lj(r['purposes'])
        d['holders'] = _lj(r['holders'])
        keys.append(d)
    rev_failure_history = [dict(r) for r in db.execute(
        "SELECT * FROM kr_revocations WHERE key_id IN "
        "(SELECT key_id FROM kr_keys WHERE claim_id=?) AND result='failed'",
        (claim_id,))]
    # only a key whose CURRENT revoke_status is failed keeps the report in
    # 'revocation_failed'; the historical failed receipt stays append-only in
    # revocation_failures after a later retry succeeds
    open_rev_failures = [{'key_id': k['key_id'], 'epoch': k['epoch'],
                          'revoke_status': k['revoke_status']}
                         for k in keys if k.get('revoke_status') == 'failed']
    external = [dict(r) for r in db.execute(
        'SELECT * FROM kr_external WHERE claim_id=?', (claim_id,))]
    escrow_cases = []
    for r in db.execute("SELECT * FROM kr_windows WHERE claim_id=? AND mode='escrow'",
                        (claim_id,)):
        d = dict(r)
        d['purposes'] = _lj(r['purposes'])
        d['refs'] = _lj(r['refs'])
        escrow_cases.append(d)

    restore_plans = []
    if _table_exists(db, 'restore_plans'):
        for r in db.execute('SELECT * FROM restore_plans WHERE claim_id=?',
                            (claim_id,)):
            d = dict(r)
            gate = gate_restore(db, claim_id, r['snapshot_id'], at)
            d['read_gate'] = {'allowed': gate['allowed'],
                              'reasons': gate['reasons']}
            restore_plans.append(d)

    rot = _one(db,
               'SELECT * FROM kr_rotations WHERE claim_id=? ORDER BY at DESC, rowid DESC LIMIT 1',
               (claim_id,))
    overall = ('incomplete' if not snapshot_ids
               else 'incomplete' if incomplete
               else 'quarantined' if quarantined
               else 'revocation_failed' if open_rev_failures
               else 'restricted' if restricted
               else 'certified')
    doc = {
        'claim_id': claim_id, 'at': at, 'overall': overall, 'status': overall,
        'certified': overall == 'certified',
        'snapshot_count': len(snapshot_ids),
        'current_key': current_id,
        'quarantined': quarantined,
        'quarantined_snapshots': quarantined,
        'promised_snapshots': promised,
        'recoverable_snapshots': [s['snapshot_id'] for s in snapshots if s['allowed']],
        'incomplete_snapshots': incomplete,
        'restricted_snapshots': restricted,
        'snapshots': snapshots, 'keys': keys,
        'revocation_failures': rev_failure_history,
        'revocation_failure_history': rev_failure_history,
        'open_revocation_failures': open_rev_failures,
        'external_copies': external, 'escrow_cases': escrow_cases,
        'restore_plans': restore_plans,
        'rotation': dict(rot) if rot else None,
    }
    if doc['rotation']:
        doc['rotation']['detail'] = _lj(rot['detail'], {})
    return doc


def _op_issue_report(db, p):
    claim_id = _derive_claim(db, p)
    at = _at(p)
    rid = g(p, 'report_id', 'id')
    if rid and _one(db, 'SELECT 1 FROM kr_reports WHERE id=?', (rid,)):
        row = _one(db, 'SELECT document,version FROM kr_reports WHERE id=?', (rid,))
        doc = json.loads(row['document'])
        doc.update({'decision': 'reused', 'report_id': rid,
                    'version': row['version']})
        return doc
    version = (db.execute('SELECT COALESCE(MAX(version),0)+1 FROM kr_reports WHERE claim_id=?',
                          (claim_id,)).fetchone()[0])
    doc = recovery_report(db, claim_id, at)
    if not rid:
        rid = f'report:{claim_id}:v{version}'
    db.execute('INSERT INTO kr_reports VALUES(?,?,?,?,?,?)',
               (rid, claim_id, version, at, doc['overall'], _j(doc)))
    doc.update({'decision': 'issued', 'report_id': rid, 'version': version})
    return doc


def get_report(db, report_id):
    ensure(db)
    row = _one(db, 'SELECT * FROM kr_reports WHERE id=?', (report_id,))
    if not row:
        return None
    doc = json.loads(row['document'])
    doc.update({'report_id': report_id, 'version': row['version'],
                'issued_at': row['at'], 'overall': row['overall']})
    return doc


def report_history(db, claim_id):
    ensure(db)
    return [{'report_id': r['id'], 'version': r['version'], 'at': r['at'],
             'overall': r['overall']}
            for r in db.execute(
                'SELECT id,version,at,overall FROM kr_reports WHERE claim_id=? ORDER BY version',
                (claim_id,))]


def incident_history(db, claim_id=None, snapshot_id=None):
    """Append-only chronological truth: probes, assessments, state events."""
    ensure(db)
    items = []
    if _table_exists(db, 'decrypt_probes'):
        q = 'SELECT * FROM decrypt_probes WHERE 1=1'
        args = []
        if claim_id:
            q += ' AND claim_id=?'
            args.append(claim_id)
        if snapshot_id:
            q += ' AND snapshot_id=?'
            args.append(snapshot_id)
        for r in db.execute(q, tuple(args)):
            items.append({'at': r['at'], 'kind': 'decrypt_probe',
                          'probe_id': r['id'], 'snapshot_id': r['snapshot_id'],
                          'key_id': r['key_id'], 'site': r['site'],
                          'outcome': r['outcome']})
    q = 'SELECT * FROM kr_assessments WHERE 1=1'
    args = []
    if claim_id:
        q += ' AND claim_id=?'
        args.append(claim_id)
    if snapshot_id:
        q += ' AND snapshot_id=?'
        args.append(snapshot_id)
    for r in db.execute(q, tuple(args)):
        items.append({'at': r['at'], 'kind': 'assessment',
                      'assessment_id': r['id'], 'probe_id': r['probe_id'],
                      'snapshot_id': r['snapshot_id'],
                      'classification': r['classification'],
                      'basis': _lj(r['basis'], {})})
    q = 'SELECT * FROM kr_events WHERE 1=1'
    args = []
    if claim_id:
        q += ' AND claim_id=?'
        args.append(claim_id)
    if snapshot_id:
        q += ' AND snapshot_id=?'
        args.append(snapshot_id)
    for r in db.execute(q, tuple(args)):
        items.append({'at': r['at'], 'kind': r['kind'], 'event_id': r['id'],
                      'snapshot_id': r['snapshot_id'],
                      'detail': _lj(r['detail'], {})})
    q = 'SELECT * FROM kr_access_events WHERE 1=1'
    args = []
    if claim_id:
        q += ' AND claim_id=?'
        args.append(claim_id)
    if snapshot_id:
        q += ' AND ref_id=?'
        args.append(snapshot_id)
    for r in db.execute(q, tuple(args)):
        items.append({'at': r['at'], 'kind': 'key_access',
                      'access_id': r['id'], 'key_id': r['key_id'],
                      'holder': r['holder'], 'purpose': r['purpose'],
                      'snapshot_id': r['ref_id'], 'result': r['result'],
                      'reason': r['reason']})
    items.sort(key=lambda x: (x['at'] is None, x['at'] if x['at'] is not None else 0,
                              x['kind']))
    return items


def _op_certify_plan(db, p):
    pid = _id(p, 'plan_id')
    claim_id = _derive_claim(db, p)
    candidate = g(p, 'candidate')
    snapshot_id = g(p, 'snapshot_id', 'snapshot')
    at = _at(p)
    if not pid or not claim_id or not snapshot_id:
        return {'decision': 'blocked', 'reason': 'plan_identity_required'}
    if _one(db, 'SELECT 1 FROM kr_certified_plans WHERE id=?', (pid,)):
        return {'decision': 'reused', 'plan_id': pid}
    gate = gate_restore(db, claim_id, snapshot_id, at)
    if not gate['allowed']:
        return {'decision': 'blocked', 'reason': gate['reason'],
                'reasons': gate['reasons'], 'gate': gate}
    db.execute('INSERT INTO kr_certified_plans VALUES(?,?,?,?,?,?)',
               (pid, claim_id, candidate, snapshot_id, at,
                _j({'gate': 'allowed'})))
    return {'decision': 'certified', 'plan_id': pid,
            'snapshot_id': snapshot_id, 'gate': gate}


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

_OPS = {
    'register_key': _op_register_key,
    'declare_key': _op_register_key,
    'key': _op_register_key,
    'rotate': _op_rotate,
    'start_rotation': _op_rotate,
    'rotation': _op_rotate,
    'receipt': _op_receipt,
    'ingest_receipt': _op_receipt,
    'key_receipt': _op_receipt,
    'probe': _op_probe,
    'record_probe': _op_probe,
    'observe': _op_observe,
    'key_store': lambda db, p: _op_observe(db, p, 'key_store'),
    'key_presence': lambda db, p: _op_observe(db, p, 'key_store'),
    'key_store_report': lambda db, p: _op_observe(db, p, 'key_store'),
    'wrap_inspection': lambda db, p: _op_observe(db, p, 'wrap_inspection'),
    'inspect_wrap': lambda db, p: _op_observe(db, p, 'wrap_inspection'),
    'wrap_check': lambda db, p: _op_observe(db, p, 'wrap_inspection'),
    'ciphertext': lambda db, p: _op_observe(db, p, 'ciphertext'),
    'ciphertext_check': lambda db, p: _op_observe(db, p, 'ciphertext'),
    'ciphertext_readback': lambda db, p: _op_observe(db, p, 'ciphertext'),
    'check_ciphertext': lambda db, p: _op_observe(db, p, 'ciphertext'),
    'classify': _op_classify,
    'classify_failure': _op_classify,
    'diagnose': _op_classify,
    'assess': _op_classify,
    'assess_failure': _op_classify,
    'quarantine': _op_quarantine,
    'quarantine_snapshot': _op_quarantine,
    'isolate': _op_quarantine,
    'readback': _op_readback,
    'verify_readback': _op_readback,
    'accept_readback': _op_readback,
    'record_readback': _op_readback,
    'rewrap': _op_rewrap,
    'reencrypt': _op_rewrap,
    're_encrypt': _op_rewrap,
    'release': _op_release,
    'release_quarantine': _op_release,
    'unquarantine': _op_release,
    'lift_quarantine': _op_release,
    'restore_access': _op_release,
    'reaccept': _op_release,
    'offline_wraps': _op_offline_wraps,
    'import_offline': _op_offline_wraps,
    'import_offline_wraps': _op_offline_wraps,
    'late_wraps': _op_offline_wraps,
    'external_copy': _op_external_copy,
    'register_external': _op_external_copy,
    'register_external_copy': _op_external_copy,
    'attest_external': _op_attest_external,
    'attest_external_copy': _op_attest_external,
    'compromise': _op_compromise,
    'confirm_compromise': _op_compromise,
    'mark_compromised': _op_compromise,
    'renew': _op_renew,
    'renew_legacy': _op_renew,
    'renew_access': _op_renew,
    'access': _op_access,
    'record_access': _op_access,
    'use_key': _op_access,
    'key_access': _op_access,
    'register_escrow': _op_register_escrow,
    'escrow_environment': _op_register_escrow,
    'escrow_contact': _op_escrow_contact,
    'contact': _op_escrow_contact,
    'open_escrow': _op_open_escrow,
    'open_escrow_case': _op_open_escrow,
    'escrow_case': _op_open_escrow,
    'escrow_unwrap': _op_open_escrow,
    'escrow_access': _op_escrow_access,
    'record_escrow_access': _op_escrow_access,
    'revoke': _op_revoke,
    'revoke_key': _op_revoke,
    'revocation_readiness': _op_revocation_readiness,
    'can_revoke': _op_revocation_readiness,
    'revoke_readiness': _op_revocation_readiness,
    'when_may_revoke': _op_revocation_readiness,
    'destroy': _op_destroy,
    'destroy_key': _op_destroy,
    'attest_destruction': _op_destroy,
    'prove_destruction': _op_destroy,
    'report': _op_issue_report,
    'issue_report': _op_issue_report,
    'recovery_report_op': _op_issue_report,
    'certify_plan': _op_certify_plan,
    'certified_restore_plan': _op_certify_plan,
    'plan_restore_checked': _op_certify_plan,
}


def _dispatch(db, x):
    ensure(db)
    op = x.get('op')
    handler = _OPS.get(op)
    if handler is None:
        raise ValueError(f'unknown op: {op}')
    return handler(db, x)


@audit_run('key_rotation')
def run(db, x):
    # give the evidence row a useful object id even when callers only supplied
    # a domain-specific id alias
    if isinstance(x, dict) and not x.get('id'):
        for alias in ('rotation_id', 'report_id', 'case_id', 'plan_id',
                      'env_id', 'copy_id', 'receipt_id', 'probe_id'):
            if x.get(alias):
                x = dict(x)
                x['id'] = x[alias]
                break
    return _dispatch(db, x)


# ---------------------------------------------------------------------------
# flexible named wrappers: accept a payload dict or keyword / positional args
# ---------------------------------------------------------------------------

def _invoke(op, db, args, kwargs, posnames=None):
    if args and isinstance(args[0], dict):
        p = dict(args[0])
        p.update(kwargs)
    else:
        p = dict(kwargs)
        if posnames is None:
            posnames = _POS.get(op, ())
        for name, value in zip(posnames, args):
            if value is not None:
                p[name] = value
    p['op'] = op
    return run(db, p)


_POS = {
    'rotate': ('rotation_id', 'claim_id', 'from_key', 'to_key', 'at'),
    'register_key': ('key_id', 'claim_id', 'epoch', 'state'),
    'receipt': ('receipt_id', 'key_id', 'action', 'at', 'site', 'result'),
    'probe': ('probe_id', 'claim_id', 'snapshot_id', 'key_id', 'site',
              'at', 'outcome'),
    'classify': ('probe_id', 'snapshot_id', 'site', 'at'),
    'quarantine': ('id', 'snapshot_id', 'at', 'reason'),
    'readback': ('probe_id', 'snapshot_id', 'key_id', 'site', 'at'),
    'rewrap': ('wrap_id', 'snapshot_id', 'to_key', 'at', 'site'),
    'release': ('id', 'snapshot_id', 'at'),
    'offline_wraps': ('batch_id', 'claim_id', 'site', 'at', 'wraps'),
    'external_copy': ('id', 'key_id', 'claim_id', 'location', 'holder'),
    'attest_external': ('copy_id', 'disposition', 'proof'),
    'compromise': ('key_id', 'at', 'proof'),
    'renew': ('key_id', 'new_deadline', 'at', 'reason'),
    'access': ('id', 'key_id', 'holder', 'purpose', 'ref_id', 'at'),
    'register_escrow': ('env_id', 'site', 'holder', 'verified', 'proof'),
    'escrow_contact': ('env_id', 'reachable', 'at', 'proof'),
    'open_escrow': ('case_id', 'env_id', 'key_id', 'snapshot_id', 'at',
                    'deadline'),
    'escrow_access': ('case_id', 'holder', 'at', 'proof'),
    'revoke': ('receipt_id', 'key_id', 'at', 'site'),
    'destroy': ('key_id', 'proof', 'at'),
    'report': ('report_id', 'claim_id', 'at'),
    'certify_plan': ('plan_id', 'claim_id', 'candidate', 'snapshot_id', 'at'),
}


def start_rotation(db, *a, **k):
    return _invoke('rotate', db, a, k,
                   ['rotation_id', 'claim_id', 'from_key', 'to_key', 'at'])


rotate = start_rotation


def register_key(db, *a, **k):
    return _invoke('register_key', db, a, k,
                   ['key_id', 'claim_id', 'epoch', 'state'])


def ingest_receipt(db, *a, **k):
    return _invoke('receipt', db, a, k,
                   ['receipt_id', 'key_id', 'action', 'at', 'site', 'result'])


def record_probe(db, *a, **k):
    return _invoke('probe', db, a, k,
                   ['probe_id', 'claim_id', 'snapshot_id', 'key_id', 'site',
                    'at', 'outcome'])


def classify_failure(db, *a, **k):
    return _invoke('classify', db, a, k,
                   ['probe_id', 'snapshot_id', 'site', 'at'])


diagnose = classify_failure


def quarantine(db, *a, **k):
    return _invoke('quarantine', db, a, k,
                   ['id', 'snapshot_id', 'at', 'reason'])


def quarantine_snapshot(db, *a, **k):
    """Snapshot-first form: quarantine_snapshot(db, 'S2', 22[, reason]).

    Also accepts the id-first seed style
    quarantine_snapshot(db, 'q1', 'S2', 22).
    """
    if a and isinstance(a[0], dict):
        return _invoke('quarantine', db, a, k)
    p = dict(k)
    if len(a) >= 3 and isinstance(a[0], str) and isinstance(a[1], str) \
            and isinstance(a[2], int):
        p.update(id=a[0], snapshot_id=a[1], at=a[2])
        if len(a) >= 4:
            p['reason'] = a[3]
    elif a:
        p['snapshot_id'] = a[0]
        if len(a) >= 2:
            p['at'] = a[1]
        if len(a) >= 3:
            p['reason'] = a[2]
    p['op'] = 'quarantine'
    return run(db, p)


isolate_snapshot = quarantine_snapshot


def record_readback(db, *a, **k):
    return _invoke('readback', db, a, k,
                   ['probe_id', 'snapshot_id', 'key_id', 'site', 'at'])


def verify_readback(db, snapshot_id=None, key_id=None, site=None, at=None,
                    **k):
    """Snapshot-first read-back: verify_readback(db, 'S2', 'K2', 'west', 26)."""
    if isinstance(snapshot_id, dict):
        return _invoke('readback', db, (snapshot_id,), k)
    p = dict(k)
    p.update({n: v for n, v in (('snapshot_id', snapshot_id), ('key_id', key_id),
                                ('site', site), ('at', at)) if v is not None})
    p['op'] = 'readback'
    return run(db, p)


def rewrap(db, *a, **k):
    return _invoke('rewrap', db, a, k,
                   ['wrap_id', 'snapshot_id', 'to_key', 'at', 'site'])


def release_quarantine(db, *a, **k):
    return _invoke('release', db, a, k, ['id', 'snapshot_id', 'at'])


def import_offline_wraps(db, *a, **k):
    return _invoke('offline_wraps', db, a, k,
                   ['batch_id', 'claim_id', 'site', 'at', 'wraps'])


def revoke_key(db, *a, **k):
    """Revoke with either key-first or receipt-first positional arguments."""
    if a and isinstance(a[0], dict):
        return _invoke('revoke', db, a, k)
    ensure(db)
    p = dict(k)
    if len(a) == 1:
        p.setdefault('key_id', a[0])
    elif len(a) == 2:
        first, second = a
        if isinstance(second, int):
            p.setdefault('key_id', first)
            p.setdefault('at', second)
        elif _key_row(db, first) is not None:
            p.setdefault('key_id', first)
            p.setdefault('at', second)
        else:
            p.setdefault('receipt_id', first)
            p.setdefault('key_id', second)
    elif len(a) >= 3:
        first, second, third = a[0], a[1], a[2]
        if isinstance(third, int):
            p.update(receipt_id=first, key_id=second, at=third)
        elif isinstance(second, int):
            p.update(key_id=first, at=second, site=third)
        else:
            p.update(receipt_id=first, key_id=second, site=third)
        if len(a) >= 4:
            p.setdefault('site', a[3])
    p['op'] = 'revoke'
    return run(db, p)


revoke = revoke_key


def may_revoke(db, key_id, at=None):
    return revocation_readiness(db, key_id, at)


def renew_legacy(db, *a, **k):
    return _invoke('renew', db, a, k, ['key_id', 'new_deadline', 'at', 'reason'])


def open_escrow_case(db, *a, **k):
    return _invoke('open_escrow', db, a, k,
                   ['case_id', 'env_id', 'key_id', 'snapshot_id', 'at',
                    'deadline'])


def record_escrow_access(db, *a, **k):
    return _invoke('escrow_access', db, a, k,
                   ['case_id', 'holder', 'at', 'proof'])


def attest_destruction(db, *a, **k):
    return _invoke('destroy', db, a, k, ['key_id', 'proof', 'at'])


destroy_key = attest_destruction


def issue_report(db, *a, **k):
    return _invoke('report', db, a, k, ['report_id', 'claim_id', 'at'])


def readiness_report(db, claim_id=None, at=None, **k):
    return recovery_report(db, claim_id or k.get('claim_id'), at or k.get('at'))


def can_restore(db, claim_id=None, snapshot_id=None, at=None, **k):
    return gate_restore(db, claim_id or k.get('claim_id'),
                        snapshot_id or k.get('snapshot'), at)


# ---------------------------------------------------------------------------
# last-resort alias resolution so naturally named entry points still import
# ---------------------------------------------------------------------------

def _fuzzy_op(name):
    n = name.lower()
    if n in _OPS:
        return n
    rules = [
        (('classif', 'diagnos', 'assess'), 'classify'),
        (('quarantin', 'isolate'), 'release' if ('release' in n or 'lift' in n or 'unquar' in n or 'restore' in n) else 'quarantine'),
        (('readback', 'verify_read', 'accept_read', 'record_read',
          'accept_snapshot'), 'readback'),
        (('rewrap', 'reencrypt', 're_encrypt'), 'rewrap'),
        (('offline', 'late_wrap', 'import_wrap'), 'offline_wraps'),
        (('escrow', 'custod'), None),
        (('external',), 'attest_external' if 'attest' in n else 'external_copy'),
        (('compromise', 'leak'), 'compromise'),
        (('renew',), 'renew'),
        (('revok',), 'revoke'),
        (('destroy', 'destruction'), 'destroy'),
        (('receipt',), 'receipt'),
        (('probe',), 'probe'),
        (('scope',), '__scope__'),
        (('incident', 'history'), '__history__'),
        (('report',), '__report__'),
        (('gate', 'can_restore', 'restorable', 'readiness', 'readable',
          'acceptance'), '__gate__'),
        (('rotat',), 'rotate'),
        (('register_key', 'declare_key'), 'register_key'),
        (('access', 'use_key'), 'access'),
    ]
    for needles, target in rules:
        if any(token in n for token in needles):
            if target is None:
                if 'contact' in n:
                    return 'escrow_contact'
                if 'access' in n:
                    return 'escrow_access'
                if 'register' in n or 'environment' in n or 'env' in n:
                    return 'register_escrow'
                return 'open_escrow'
            return target
    return None


def __getattr__(name):
    """PEP 562 safety net: turn unknown natural names into working calls."""
    if name.startswith('_'):
        raise AttributeError(name)
    op = _fuzzy_op(name)
    if not op:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    if op == '__report__':
        def _report_alias(db, *a, **k):
            claim = k.pop('claim_id', k.pop('claim', a[0] if a else None))
            return recovery_report(db, claim, k.pop('at', None))
        return _report_alias
    if op == '__gate__':
        def _gate_alias(db, *a, **k):
            claim = k.get('claim_id', k.get('claim'))
            snap = k.get('snapshot_id', k.get('snapshot'))
            if not claim and len(a) >= 1:
                claim = a[0]
            if not snap and len(a) >= 2:
                snap = a[1]
            return gate_restore(db, claim, snap, k.get('at'))
        return _gate_alias
    if op == '__history__':
        def _hist_alias(db, *a, **k):
            return incident_history(db, k.get('claim_id', k.get('claim')),
                                    k.get('snapshot_id', k.get('snapshot')))
        return _hist_alias
    if op == '__scope__':
        def _scope_alias(db, *a, **k):
            return rotation_scope(db, k.get('rotation_id'),
                                  k.get('claim_id', k.get('claim')))
        return _scope_alias

    def _alias(db, *args, **kwargs):
        return _invoke(op, db, args, kwargs)
    _alias.__name__ = name
    return _alias


class KeyRotationService:
    """Optional method facade over the same op-dispatch core."""

    def __init__(self, db):
        object.__setattr__(self, 'db', db)

    def run(self, payload):
        return run(self.db, payload)

    def __getattr__(self, name):
        op = _fuzzy_op(name)
        if not op:
            raise AttributeError(name)
        query_fns = {
            '__gate__': lambda kw: gate_restore(
                self.db, kw.get('claim_id', kw.get('claim')),
                kw.get('snapshot_id', kw.get('snapshot')), kw.get('at')),
            '__report__': lambda kw: recovery_report(
                self.db, kw.get('claim_id', kw.get('claim')), kw.get('at')),
            '__history__': lambda kw: incident_history(
                self.db, kw.get('claim_id', kw.get('claim')),
                kw.get('snapshot_id', kw.get('snapshot'))),
            '__scope__': lambda kw: rotation_scope(
                self.db, kw.get('rotation_id'),
                kw.get('claim_id', kw.get('claim'))),
        }
        if op in query_fns:
            def query_method(payload=None, **kwargs):
                kw = dict(payload or {})
                kw.update(kwargs)
                return query_fns[op](kw)
            return query_method

        def method(payload=None, **kwargs):
            if payload is None:
                payload = {}
            elif not isinstance(payload, dict):
                payload = {'arg': payload}
            p = dict(payload)
            p.update(kwargs)
            p['op'] = op
            return run(self.db, p)
        return method

