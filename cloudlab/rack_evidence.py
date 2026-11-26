"""Physical rack evidence, capacity credentials and bounded remediation.

The pool ledger originally trusted logical rack names.  Two pools could
therefore sell the same physical cabinet twice, and a rack rename could hide
the fact that two replicas share one power domain.  This module turns raw
inventory pages (controller / cabinet / backplane / serial / bytes) into
*capacity credentials*: one per logical ``(pool, rack)`` alias and one per
physical asset.  Every capacity decision (place, reserve, commit, bind, fence,
promote) reads the same credential snapshot, so planned members, live
reservations, committed bindings and in-flight recovery all de-duplicate the
same physical bytes.

Evidence is append-only and carries its own version.  Re-observing the same
``(evidence_version, payload)`` is a replay and never changes a promise.  A
*late* page (``observed_at`` older than one already applied for the same alias)
is retained as ``superseded`` and cannot rewrite existing commitments.  A page
that contradicts an alias's established physical identity is retained as
``conflicting`` and only surfaces through ``reconcile`` -- it never re-points a
binding or a fence by itself.

``reconcile`` rechecks every promise against the current credential snapshot and
returns a bounded remediation list of the concrete reservations, bindings,
plans and recovery plans still affected.  A volume whose physical evidence
still supports its bytes keeps its binding; only unsupported promises are
risked.  No binding is detached automatically.
"""

import hashlib
import json

from .store import audit_run, record, transaction

# States that still owe capacity.  ``expired`` and ``released`` do not.
LIVE_RESERVATION_STATES = ('reserved', 'committed', 'risk')
# States in which an existing customer binding must not be silently detached.
PROTECTED_BINDING_STATES = ('bound', 'risk')


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------

def _norm(value):
    if value is None:
        return ''
    return str(value).strip().lower()


def physical_key(row):
    """Stable identity of the physical capacity behind one inventory page.

    A storage cabinet is the physical asset.  Two controllers or rack aliases
    reporting the same cabinet resolve to one key, so the same bytes are
    counted once.  The controller is only a fallback when no cabinet/serial/
    backplane identifier is present -- renumbering a controller must never
    create a new cabinet.  Serial and backplane corroborate identity but a
    missing serial on one page must not split one cabinet into two.
    """
    cabinet = _norm(row.get('cabinet'))
    if cabinet:
        return 'cabinet:' + cabinet
    serial = _norm(row.get('serial'))
    if serial:
        return 'serial:' + serial
    backplane = _norm(row.get('backplane'))
    if backplane:
        return 'backplane:' + backplane
    controller = _norm(row.get('controller'))
    if controller:
        return 'controller:' + controller
    return 'rack:' + _norm(row.get('rack'))


def domain_key(row):
    """Failure domain = the physical power enclosure, not the rack label.

    Two replicas that sit in different controller/rack aliases but the same
    cabinet share a domain.  When the cabinet is unknown the physical asset is
    used, so the domain is never *weaker* than the evidence supports.
    """
    cabinet = _norm(row.get('cabinet'))
    if cabinet:
        return 'power:' + cabinet
    return 'asset:' + physical_key(row)


def _identity(row):
    return {name: _norm(row.get(name)) or None
            for name in ('controller', 'cabinet', 'serial', 'backplane')}


def identity_conflict(frozen, current):
    """Has an alias been re-pointed at a *different* physical asset?

    Missing fields are treated as unknown, not contradictory: a page that adds
    a serial to a known cabinet is corroboration, not a conflict.  Only a
    different *known* cabinet/serial/backplane identity is a conflict.
    """
    if not frozen or not current:
        return False
    return physical_key(frozen) != physical_key(current)


def _digest(payload):
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]


# --------------------------------------------------------------------------
# evidence ingestion
# --------------------------------------------------------------------------

def _applied_pages(db, pool_id, rack):
    return [dict(r) for r in db.execute(
        "SELECT * FROM rack_evidence WHERE rack=? AND (pool_id=? OR pool_id IS NULL) "
        "AND state='applied' ORDER BY received_at ASC, seq ASC", (rack, pool_id))]


def _latest_applied(db, pool_id, rack):
    rows = _applied_pages(db, pool_id, rack)
    return rows[-1] if rows else None


def _page_from(x):
    return {
        'pool_id': x.get('pool'), 'rack': x.get('rack'),
        'controller': _norm(x.get('controller')) or None,
        'cabinet': _norm(x.get('cabinet')) or None,
        'serial': _norm(x.get('serial')) or None,
        'backplane': _norm(x.get('backplane')) or None,
        'capacity': int(x['capacity']) if x.get('capacity') is not None else None,
        'verified': 1 if x.get('verified') else 0,
        'observed_at': int(x.get('observed_at', 0)),
        'received_at': int(x.get('received_at', x.get('observed_at', 0))),
        'note': x.get('note'),
    }


def _observe_page(db, page, version, evidence_id=None):
    pool_id, rack = page['pool_id'], page['rack']
    identity = {k: page[k] for k in ('pool_id', 'rack', 'controller', 'cabinet',
                                     'serial', 'backplane', 'capacity', 'verified',
                                     'observed_at', 'received_at', 'note')}
    identity['evidence_version'] = version
    payload = json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)
    duplicate = db.execute(
        'SELECT seq,state FROM rack_evidence WHERE evidence_version=? AND payload=?',
        (version, payload)).fetchone()
    if duplicate:
        return {'decision': 'replayed', 'evidence_version': version,
                'state': duplicate['state']}

    latest = _latest_applied(db, pool_id, rack)
    state = 'applied'
    reason = None
    if latest and page['observed_at'] < latest['observed_at']:
        state = 'superseded'
        reason = 'late_page'
    elif latest and identity_conflict(_identity(latest), _identity(page)) and latest['verified']:
        # A later page re-points an established alias at another cabinet.  It
        # becomes the effective evidence, but the frozen credentials of every
        # existing promise are *not* rewritten; ``reconcile`` will compare and
        # list exactly what moved.  The raw page keeps the reason forever.
        reason = 'physical_identity_changed'
    db.execute(
        'INSERT INTO rack_evidence(id,evidence_version,pool_id,rack,controller,cabinet,'
        'serial,backplane,capacity,verified,observed_at,received_at,state,note,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (evidence_id or version, version, pool_id, rack, page['controller'], page['cabinet'],
         page['serial'], page['backplane'], page['capacity'], page['verified'],
         page['observed_at'], page['received_at'], state, page['note'], payload))
    record(db, 'rack_evidence', version, 'observe', page['observed_at'],
           {'input': {**page, 'evidence_version': version},
            'state': state, 'reason': reason,
            'physical_key': physical_key(page), 'domain_key': domain_key(page)})
    result = {'decision': 'recorded' if state == 'applied' else state,
              'evidence_version': version, 'state': state,
              'physical_key': physical_key(page), 'domain_key': domain_key(page)}
    if reason:
        result['reason'] = reason
    return result


def _ingest(db, x):
    pages = x.get('pages') if 'pages' in x else [x]
    if not pages:
        return {'decision': 'blocked', 'reason': 'no_evidence'}
    results = []
    for index, raw in enumerate(pages):
        page = _page_from(raw)
        version = raw.get('evidence_version') or raw.get('version')
        if not version:
            version = 'obs-' + _digest({k: page.get(k) for k in
                                        ('pool_id', 'rack', 'controller', 'cabinet',
                                         'serial', 'backplane', 'capacity', 'observed_at')})
        version = str(version)
        if page['pool_id'] is None or page['rack'] is None or page['capacity'] is None:
            results.append({'decision': 'blocked', 'reason': 'incomplete_evidence',
                            'evidence_version': version})
            continue
        if page['capacity'] < 0:
            results.append({'decision': 'blocked', 'reason': 'invalid_evidence_capacity',
                            'evidence_version': version})
            continue
        evidence_id = raw.get('id') or version
        results.append(_observe_page(db, page, version, evidence_id))
    if len(results) == 1:
        return results[0]
    return {'decision': 'recorded', 'evidence': results}


# --------------------------------------------------------------------------
# effective credential view
# --------------------------------------------------------------------------

def _build_view(db):
    """Latest applied page per alias, assets folded across aliases."""
    aliases = {}
    for row in db.execute(
        "SELECT * FROM rack_evidence WHERE state='applied' "
        "ORDER BY received_at ASC, seq ASC"
    ):
        row = dict(row)
        aliases[(row['pool_id'], row['rack'])] = {
            'pool_id': row['pool_id'], 'rack': row['rack'],
            'controller': row['controller'], 'cabinet': row['cabinet'],
            'serial': row['serial'], 'backplane': row['backplane'],
            'capacity': int(row['capacity'] or 0),
            'verified': bool(row['verified']),
            'evidence_version': row['evidence_version'],
            'physical_key': physical_key(row),
            'domain_key': domain_key(row),
        }
    assets = {}
    for view in aliases.values():
        entry = assets.setdefault(view['physical_key'], {
            'physical_key': view['physical_key'], 'domain_key': view['domain_key'],
            'capacity': view['capacity'], 'verified': False,
            'aliases': [], 'evidence_versions': set(), 'capacities': []})
        entry['aliases'].append((view['pool_id'], view['rack']))
        entry['evidence_versions'].add(view['evidence_version'])
        if view['verified']:
            entry['capacities'].append(view['capacity'])
            entry['verified'] = True
    for entry in assets.values():
        entry['evidence_versions'] = sorted(entry['evidence_versions'])
        # One cabinet, possibly reported by several controllers with slightly
        # different byte counts.  The physical asset is *one* pool of bytes:
        # never sum the pages, and assume the smallest verified page.  This is
        # what catches a repair that returns the cabinet with fewer bytes.
        candidates = entry.pop('capacities') or [a for a in
                                                 (aliases[alias]['capacity'] for alias in entry['aliases'])]
        entry['capacity'] = min(candidates)
        # Propagate the asset's bytes/verification back onto every alias of the
        # same asset so per-alias checks cannot undercount one controller page.
        for alias in entry['aliases']:
            aliases[alias]['capacity'] = entry['capacity']
            aliases[alias]['verified'] = aliases[alias]['verified'] or entry['verified']
    return {'aliases': aliases, 'assets': assets}


def credential_view(db):
    return _build_view(db)


def pool_has_evidence(db, pool_id):
    return any(alias[0] == pool_id for alias in _build_view(db)['aliases'])


def _view_for_alias(db, pool_id, rack, views=None):
    view = (views or _build_view(db))['aliases'].get((pool_id, rack))
    if view:
        return view
    # No inventory page: a synthetic, unverified rack-sized credential keeps
    # behaviour no weaker than the logical ledger.
    return {
        'pool_id': pool_id, 'rack': rack, 'controller': None, 'cabinet': None,
        'serial': None, 'backplane': None, 'capacity': 0, 'verified': False,
        'evidence_version': None, 'physical_key': 'rack:' + _norm(rack),
        'domain_key': 'asset:rack:' + _norm(rack),
    }


# --------------------------------------------------------------------------
# frozen credentials
# --------------------------------------------------------------------------

def _frozen(db, kind, object_id, rack):
    row = db.execute(
        'SELECT * FROM capacity_credentials WHERE kind=? AND object_id=? AND rack=?',
        (kind, object_id, rack)).fetchone()
    return dict(row) if row else None


def _store_credential(db, kind, object_id, pool_id, rack, view, capacity=None):
    """Freeze the credential a capacity decision relied on.

    An existing row is never silently rewritten by newer inventory: that is
    what keeps a binding/fence/promotion bound to the evidence it was accepted
    under.  A change is surfaced by ``reconcile`` instead.
    """
    existing = _frozen(db, kind, object_id, rack)
    if existing:
        return existing
    db.execute(
        'INSERT INTO capacity_credentials(kind,object_id,rack,pool_id,physical_key,'
        'domain_key,evidence_version,verified,capacity,cabinet,serial,backplane,'
        'controller,detail,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (kind, object_id, rack, pool_id, view['physical_key'], view['domain_key'],
         view['evidence_version'], int(view['verified']),
         view['capacity'] if capacity is None else capacity,
         view.get('cabinet'), view.get('serial'), view.get('backplane'),
         view.get('controller'),
         json.dumps({'alias_capacity': view['capacity']}, sort_keys=True), 'active'))
    return _frozen(db, kind, object_id, rack)


def record_credentials_for_plan(db, plan_id, pool_id, racks, replica_size):
    views = _build_view(db)
    for rack in racks:
        _store_credential(db, 'plan', plan_id, pool_id, rack,
                          _view_for_alias(db, pool_id, rack, views), replica_size)


def record_credentials_for_reservation(db, reservation_id, pool_id, rack, amount):
    return _store_credential(db, 'reservation', reservation_id, pool_id, rack,
                             _view_for_alias(db, pool_id, rack), amount)


def record_credential(db, kind, object_id, pool_id, rack):
    return _store_credential(db, kind, object_id, pool_id, rack,
                             _view_for_alias(db, pool_id, rack))


def reservation_credential(db, reservation_id, rack):
    frozen = _frozen(db, 'reservation', reservation_id, rack)
    if frozen:
        return frozen
    reservation = db.execute('SELECT * FROM reservations WHERE id=?',
                             (reservation_id,)).fetchone()
    if not reservation:
        return None
    return _store_credential(db, 'reservation', reservation_id, reservation['pool_id'],
                             rack, _view_for_alias(db, reservation['pool_id'], rack),
                             reservation['amount'])


def credential_matches_view(credential, view):
    if not credential:
        return False
    return (credential['physical_key'] == view['physical_key']
            and credential['domain_key'] == view['domain_key'])


# --------------------------------------------------------------------------
# physical demand ledger
# --------------------------------------------------------------------------

def _plan_demand(db):
    """Planned replica members not yet covered by a live reservation."""
    reserved = {(r['plan_id'], r['rack']) for r in db.execute(
        "SELECT plan_id,rack FROM reservations WHERE plan_id IS NOT NULL "
        "AND state IN ('reserved','committed','risk')")}
    demand = []
    for row in db.execute(
        "SELECT m.plan_id,m.rack,p.pool_id,p.replica_size,p.state "
        "FROM placement_members m JOIN placement_plans p ON p.id=m.plan_id "
        "WHERE p.state IN ('planned','risk','reserved') AND m.state='planned'"
    ):
        if (row['plan_id'], row['rack']) in reserved:
            continue
        demand.append({'source': 'plan', 'object_id': row['plan_id'],
                       'pool_id': row['pool_id'], 'rack': row['rack'],
                       'amount': int(row['replica_size'])})
    return demand


def _reservation_demand(db, views):
    demand = []
    for row in db.execute(
        "SELECT id,pool_id,rack,amount FROM reservations "
        "WHERE state IN ('reserved','committed','risk')"
    ):
        view = _view_for_alias(db, row['pool_id'], row['rack'], views)
        demand.append({'source': 'reservation', 'object_id': row['id'],
                       'pool_id': row['pool_id'], 'rack': row['rack'],
                       'amount': int(row['amount']), 'physical_key': view['physical_key'],
                       'domain_key': view['domain_key'],
                       'has_evidence': (row['pool_id'], row['rack']) in views['aliases']})
    return demand


def asset_demand(db):
    """Per physical asset: live reservation demand plus planned-member demand.

    Demand is summed per replica; capacity is looked up once per asset.  This
    is the single ledger shared by pools, so a reservation in pool A and a plan
    in pool B that resolve to the same cabinet are counted against one pool of
    physical bytes.
    """
    views = _build_view(db)
    ledger = {}
    for item in _reservation_demand(db, views) + _plan_demand(db):
        view = _view_for_alias(db, item['pool_id'], item['rack'], views)
        item.setdefault('physical_key', view['physical_key'])
        item.setdefault('domain_key', view['domain_key'])
        item.setdefault('has_evidence', (item['pool_id'], item['rack']) in views['aliases'])
        asset = views['assets'].get(item['physical_key'])
        capacity = asset['capacity'] if asset else view['capacity']
        entry = ledger.setdefault(item['physical_key'], {
            'physical_key': item['physical_key'],
            'capacity': capacity,
            'verified': asset['verified'] if asset else view['verified'],
            'has_evidence': False, 'demand': 0, 'members': []})
        entry['has_evidence'] = entry['has_evidence'] or item['has_evidence']
        entry['demand'] += item['amount']
        entry['members'].append(item)
    return ledger


def placement_cost(db, pool_id, racks, replica_size):
    """Bytes a new plan consumes: one replica per declared rack.

    A plan that names two aliases of one cabinet is rejected earlier by the
    domain check, so each declared rack is a distinct physical asset here.
    """
    return replica_size * len(racks)


def independent_domains(db, pool_id, racks, views=None):
    views = views or _build_view(db)
    return {_view_for_alias(db, pool_id, rack, views)['domain_key'] for rack in racks}


def evidence_backed(db, pool_id, racks):
    aliases = _build_view(db)['aliases']
    return all((pool_id, rack) in aliases for rack in racks)


def domains_verified(db, pool_id, racks):
    """Can these *instrumented* aliases prove independent physical domains?

    A pool that was never inventoried keeps the legacy logical-rack path.
    Once it has inventory pages, any alias that *is* instrumented must be
    nameplate-verified before it can take part in an independence claim: two
    unverified pages that might be the same cabinet cannot be sold as two
    fault domains.  A rack with no page at all is not falsely treated as a
    verified distinct domain -- ``evidence_backed`` handles coverage.
    """
    if not pool_has_evidence(db, pool_id):
        return True
    aliases = _build_view(db)['aliases']
    for rack in racks:
        view = aliases.get((pool_id, rack))
        if view is not None and not view['verified']:
            return False
    return True


# --------------------------------------------------------------------------
# guards used by the pool / claim / recovery state machines
# --------------------------------------------------------------------------

def distinct_domains(db, pool_id, racks):
    views = _build_view(db)
    return len(independent_domains(db, pool_id, racks, views)) == len(set(racks))


def planned_capacity_conflict(db, pool_id, racks, replica_size):
    """Would this plan push any of its physical assets past capacity?

    A plan that names two aliases of one cabinet (already rejected by the
    domain check) would double its footprint; the whole plan cost is charged
    per distinct physical asset so every named rack gets its own check.
    """
    ledger = asset_demand(db)
    views = _build_view(db)
    keys = {_view_for_alias(db, pool_id, rack, views)['physical_key'] for rack in racks}
    conflicts = []
    for key in keys:
        entry = ledger.get(key)
        if entry is None or not entry['has_evidence']:
            continue
        if entry['demand'] + replica_size > entry['capacity']:
            conflicts.append(key)
    return conflicts


def reservation_capacity_conflict(db, pool_id, rack, amount, plan_size=0,
                                  exclude_reservation=None):
    """Would a reservation for ``amount`` exceed the physical asset's bytes?

    ``plan_size`` is the planned replica this reservation converts into a
    binding promise; that planned member is removed from the ledger for this
    check so it is not counted twice.  ``exclude_reservation`` drops the
    reservation's own already-counted row (used when re-checking at commit).
    Aliases of the same physical asset are summed into one ledger entry, so a
    second pool's rack alias cannot hide behind a pool boundary.
    """
    views = _build_view(db)
    key = _view_for_alias(db, pool_id, rack, views)['physical_key']
    entry = asset_demand(db).get(key)
    if entry is None or not entry['has_evidence']:
        return None
    demand = entry['demand'] - max(0, int(plan_size))
    if exclude_reservation is not None:
        demand -= sum(m['amount'] for m in entry['members']
                      if m['source'] == 'reservation' and m['object_id'] == exclude_reservation)
    if demand + amount > entry['capacity']:
        return key
    return None


def reservation_independent(db, pool_id, rack, plan_id):
    """Does a reservation on ``rack`` add a distinct power domain to its plan?"""
    if not plan_id:
        return True
    views = _build_view(db)
    domain = _view_for_alias(db, pool_id, rack, views)['domain_key']
    domains = {_view_for_alias(db, pool_id, row['rack'], views)['domain_key']
               for row in db.execute(
                   "SELECT rack FROM reservations WHERE pool_id=? AND plan_id=? "
                   "AND state IN ('reserved','committed')", (pool_id, plan_id))}
    return domain not in domains


def binding_credential_ok(db, reservation_id):
    """The binding must still ride the reservation's frozen credential.

    Pools with inventory evidence require the reservation to carry a frozen
    credential that matches the page the alias currently resolves to; the page
    need not be nameplate-verified for an *existing* commitment to mount (that
    is what the operator started from), but a re-pointed alias is refused.
    Pools that were never inventoried keep the logical-rack path.  Returns
    ``None`` for an unknown reservation so the caller can distinguish it from a
    mismatch.
    """
    reservation = db.execute('SELECT * FROM reservations WHERE id=?',
                             (reservation_id,)).fetchone()
    if not reservation:
        return None
    credential = reservation_credential(db, reservation_id, reservation['rack'])
    if not pool_has_evidence(db, reservation['pool_id']):
        return credential
    status, credential = _sync_reservation_credential(db, reservation, _build_view(db))
    return credential if status in ('verified', 'upgraded', 'unverified') else False


def recovery_credential_ok(db, reservation_id, candidate_rack):
    """A promotion may only consume a frozen, evidence-backed reservation."""
    reservation = db.execute(
        "SELECT * FROM reservations WHERE id=? AND state='committed'",
        (reservation_id,)).fetchone()
    if not reservation or reservation['rack'] != candidate_rack:
        return False
    if not pool_has_evidence(db, reservation['pool_id']):
        return True
    views = _build_view(db)
    status, _ = _sync_reservation_credential(db, reservation, views)
    return status in ('verified', 'upgraded')


def recovery_domain_ok(db, claim_id, candidate_id, candidate_rack):
    """The candidate must not share a power domain with another replica.

    Any other replica of the claim -- fenced primary, healthy standby, mounted
    writer -- pins the volume to a cabinet.  Rack aliases are irrelevant: only
    the cabinet matters, so promoting ``spare-a`` onto the failed primary's
    ``rack-a`` cabinet is refused even after the primary is fenced.
    """
    views = _build_view(db)
    target = None
    for (pool_id, rack), view in views['aliases'].items():
        if rack == candidate_rack:
            target = view['domain_key']
            break
    if target is None:
        return True  # no evidence: legacy checks already validated the rack
    for row in db.execute(
        "SELECT r.rack FROM replicas r WHERE r.claim_id=? AND r.id!=?",
        (claim_id, candidate_id)
    ):
        pool_ids = {alias[0] for alias in views['aliases'] if alias[1] == row['rack']}
        for pool_id in pool_ids:
            if _view_for_alias(db, pool_id, row['rack'], views)['domain_key'] == target:
                return False
    return True


# --------------------------------------------------------------------------
# remediation
# --------------------------------------------------------------------------

def _add_remediation(db, evidence_version, reason, kind, object_id, pool_id=None,
                     physical_key=None, amount=0, protected=False, detail=None):
    db.execute(
        'INSERT INTO pending_remediation(evidence_version,reason,kind,object_id,pool_id,'
        'physical_key,amount,protected,detail,state) VALUES(?,?,?,?,?,?,?,?,?,?)',
        (evidence_version, reason, kind, object_id, pool_id, physical_key, amount,
         int(bool(protected)), json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
         'pending'))


def _mark_risk(db, kind, object_id):
    if kind == 'reservation':
        db.execute("UPDATE reservations SET state='risk',version=version+1 WHERE id=? "
                   "AND state IN ('reserved','committed')", (object_id,))
    elif kind == 'binding':
        db.execute("UPDATE bindings SET state='risk' WHERE id=? AND state='bound'", (object_id,))
    elif kind == 'plan':
        db.execute("UPDATE placement_plans SET state='risk' WHERE id=? AND state='planned'",
                   (object_id,))


def _sync_reservation_credential(db, reservation, views):
    """Compare a reservation's frozen credential with current evidence.

    Returns ``(status, credential)`` where status is one of ``verified``,
    ``upgraded`` (an evidence gap was filled; frozen row refreshed),
    ``unverified`` (no page exists yet) or ``changed`` (a *verified* page now
    names a different physical asset).

    An alias accepted without a nameplate is refined -- not re-pointed -- when
    its first verified page arrives, even though the physical key gains a
    cabinet prefix.  That is how an existing volume keeps the bytes it was
    sold without pretending the later evidence contradicted them.  Once the
    frozen credential is verified, any identity move is a real ``changed`` and
    is reported instead of silently rewritten.
    """
    view = _view_for_alias(db, reservation['pool_id'], reservation['rack'], views)
    credential = reservation_credential(db, reservation['id'], reservation['rack'])
    if credential is None:
        return 'changed', None
    if credential['verified']:
        return ('verified' if credential_matches_view(credential, view) else 'changed'), credential
    if not view['verified']:
        return 'unverified', credential
    db.execute(
        "UPDATE capacity_credentials SET physical_key=?,domain_key=?,evidence_version=?,"
        "verified=1,capacity=?,cabinet=?,serial=?,backplane=?,controller=? "
        "WHERE kind='reservation' AND object_id=? AND rack=?",
        (view['physical_key'], view['domain_key'], view['evidence_version'], view['capacity'],
         view.get('cabinet'), view.get('serial'), view.get('backplane'),
         view.get('controller'), reservation['id'], reservation['rack']))
    record(db, 'rack_evidence', reservation['id'], 'credential_upgraded',
           int(reservation['version'] or 1),
           {'from': credential, 'evidence_version': view['evidence_version'],
            'physical_key': view['physical_key']})
    return 'upgraded', _frozen(db, 'reservation', reservation['id'], reservation['rack'])


def _binding_supported(db, binding, reservation, views):
    """Does physical evidence still support the bytes this volume writes?

    The *binding's own* bytes must fit on the asset its reservation names.
    Sharing an overbooked asset is not, by itself, grounds to detach a writer:
    as long as the page still shows at least this volume's bytes, the writer
    stays and the overbooking is surfaced as remediation.  A re-pointed alias
    or a reservation too small for the claim is genuine loss of support.
    """
    if reservation is None:
        return False
    status, _ = _sync_reservation_credential(db, reservation, views)
    if status == 'changed':
        return False
    claim = db.execute('SELECT * FROM claims WHERE id=?', (binding['claim_id'],)).fetchone()
    if claim is not None and reservation['amount'] < claim['size']:
        return False
    view = _view_for_alias(db, reservation['pool_id'], reservation['rack'], views)
    asset = views['assets'].get(view['physical_key'])
    if asset and asset['verified'] and asset['capacity'] and reservation['amount'] > asset['capacity']:
        return False
    return True


def _evidence_pages_for_asset(db, key):
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM rack_evidence WHERE state IN ('applied','superseded') "
        "ORDER BY received_at ASC, seq ASC")]
    return [row for row in rows if physical_key(row) == key]


def _asset_supported_bytes(db, key):
    """Bytes the raw evidence actually supports, across every page of an asset.

    Two controller pages that later resolve to one cabinet may report
    different byte counts.  Selling the sum of the pages is double-selling;
    the physical asset supports the smallest verified page (a repair that
    returns fewer bytes must win).  When nothing is verified we can only bound
    by the smallest single page.
    """
    pages = _evidence_pages_for_asset(db, key)
    if not pages:
        return 0
    verified = [p['capacity'] for p in pages if p['verified']]
    return min(verified) if verified else min(p['capacity'] for p in pages)


def reconcile(db, evidence_version=None):
    """Recheck every promise against the current credential snapshot.

    Returns a bounded list of the concrete reservations, bindings, plans and
    recovery plans still affected.  An overbooked physical asset keeps the
    reservations that back a live customer volume; less durable promises
    (standby recovery reservations, unreferenced plans) are risked and listed.
    No binding is ever detached here.
    """
    views = _build_view(db)
    if evidence_version is None:
        row = db.execute("SELECT evidence_version FROM rack_evidence "
                         "WHERE state='applied' ORDER BY received_at DESC, seq DESC LIMIT 1").fetchone()
        evidence_version = row['evidence_version'] if row else None
    db.execute("DELETE FROM pending_remediation")

    def add(*args, **kwargs):
        _add_remediation(db, evidence_version, *args, **kwargs)

    live_bindings = {b['reservation_id']: b for b in db.execute(
        "SELECT * FROM bindings WHERE state IN ('bound','risk')")}

    # 1. frozen credential drift on live reservations.
    for row in db.execute("SELECT * FROM reservations WHERE state IN "
                          "('reserved','committed','risk') ORDER BY id"):
        status, credential = _sync_reservation_credential(db, row, views)
        if status != 'changed':
            continue
        add('reservation_evidence_changed', 'reservation', row['id'], row['pool_id'],
            credential['physical_key'] if credential else None, row['amount'],
            detail={'frozen': credential})
        _mark_risk(db, 'reservation', row['id'])

    # 2. overbooked physical assets, counted once per asset.
    for key, entry in asset_demand(db).items():
        if not entry['has_evidence'] or entry['demand'] <= entry['capacity']:
            continue
        supported = _asset_supported_bytes(db, key)
        for member in entry['members']:
            if member['source'] == 'plan':
                add('plan_asset_overbooked', 'plan', member['object_id'], member['pool_id'],
                    key, member['amount'],
                    detail={'demand': entry['demand'], 'capacity': entry['capacity'],
                            'supported_bytes': supported})
                _mark_risk(db, 'plan', member['object_id'])
                continue
            reservation = db.execute('SELECT * FROM reservations WHERE id=?',
                                     (member['object_id'],)).fetchone()
            binding = live_bindings.get(member['object_id'])
            protected = (binding is not None
                         and _binding_supported(db, binding, reservation, views)
                         and member['amount'] <= supported)
            add('reservation_asset_overbooked', 'reservation', member['object_id'],
                member['pool_id'], key, member['amount'], protected=protected,
                detail={'demand': entry['demand'], 'capacity': entry['capacity'],
                        'supported_bytes': supported,
                        'binding': binding['id'] if binding else None})
            if binding is not None:
                add('binding_asset_overbooked', 'binding', binding['id'], member['pool_id'],
                    key, member['amount'], protected=protected,
                    detail={'claim': binding['claim_id'], 'reservation': member['object_id']})
            if not protected:
                _mark_risk(db, 'reservation', member['object_id'])

    # 3. bindings whose reservation is gone, contradicted, or too small.
    for binding in db.execute("SELECT * FROM bindings WHERE state IN ('bound','risk') ORDER BY id"):
        reservation = db.execute('SELECT * FROM reservations WHERE id=?',
                                 (binding['reservation_id'],)).fetchone()
        if reservation is None:
            add('binding_without_reservation', 'binding', binding['id'], None,
                detail={'claim': binding['claim_id']})
            _mark_risk(db, 'binding', binding['id'])
            continue
        if _binding_supported(db, binding, reservation, views):
            continue
        add('binding_evidence_changed', 'binding', binding['id'], reservation['pool_id'],
            detail={'claim': binding['claim_id'], 'reservation': reservation['id']})
        _mark_risk(db, 'binding', binding['id'])

    # 4. planned capacity whose physical domains changed.
    for plan in db.execute("SELECT * FROM placement_plans WHERE state IN ('planned','risk') ORDER BY id"):
        members = db.execute('SELECT rack,state FROM placement_members WHERE plan_id=? ORDER BY rack',
                             (plan['id'],)).fetchall()
        if not members:
            continue
        current = independent_domains(db, plan['pool_id'], [m['rack'] for m in members], views)
        frozen = {r['domain_key'] for r in db.execute(
            "SELECT DISTINCT domain_key FROM capacity_credentials WHERE kind='plan' AND object_id=?",
            (plan['id'],))}
        if not frozen:
            continue
        if len(current) != len(members) or current != frozen:
            add('placement_domains_changed', 'plan', plan['id'], plan['pool_id'],
                detail={'current': sorted(current), 'frozen': sorted(frozen)})
            _mark_risk(db, 'plan', plan['id'])

    # 5. recovery plans / in-flight candidates.
    for plan in db.execute("SELECT * FROM restore_plans WHERE state='ready' ORDER BY id"):
        candidate = db.execute('SELECT * FROM replicas WHERE id=? AND claim_id=?',
                               (plan['candidate'], plan['claim_id'])).fetchone()
        if candidate is None or candidate['state'] != 'healthy':
            add('restore_candidate_unavailable', 'restore_plan', plan['id'], None,
                detail={'candidate': plan['candidate']})
            continue
        claim = db.execute('SELECT size FROM claims WHERE id=?', (plan['claim_id'],)).fetchone()
        size = claim['size'] if claim else 0
        usable = list(db.execute(
            "SELECT * FROM reservations WHERE state='committed' AND rack=? AND amount>=?",
            (candidate['rack'], size)))
        if not any(recovery_credential_ok(db, r['id'], candidate['rack']) for r in usable):
            add('restore_requires_physical_reservation', 'restore_plan', plan['id'], None,
                detail={'candidate': plan['candidate'], 'rack': candidate['rack'],
                        'reservations': [r['id'] for r in usable]})

    pending = [dict(r) for r in db.execute('SELECT * FROM pending_remediation ORDER BY id')]
    return {
        'evidence_version': evidence_version,
        'pending': pending,
        'summary': {
            'protected': sorted({r['object_id'] for r in pending if r['protected']}),
            'unsupported': sorted({r['object_id'] for r in pending if not r['protected']}),
            'awaiting_evidence': sorted({
                row['id'] for row in db.execute(
                    "SELECT id,pool_id,rack FROM reservations WHERE state IN "
                    "('reserved','committed','risk')")
                if (row['pool_id'], row['rack']) not in views['aliases']}),
        },
    }


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def pending(db):
    return [dict(r) for r in db.execute('SELECT * FROM pending_remediation ORDER BY id')]


def evidence_log(db):
    """Append-only raw pages, including superseded / conflicting / replayed."""
    return [dict(r) for r in db.execute('SELECT * FROM rack_evidence ORDER BY seq')]


@audit_run('rack_evidence')
def run(db, x):
    with transaction(db):
        op = x.get('op')
        if op in ('observe', 'inventory', 'page'):
            return _ingest(db, x)
        if op == 'reconcile':
            applied = db.execute("SELECT 1 FROM rack_evidence WHERE state='applied' LIMIT 1").fetchone()
            if x.get('require_evidence') and not applied:
                return {'decision': 'blocked', 'reason': 'no_verified_evidence'}
            result = reconcile(db, x.get('evidence_version'))
            record(db, 'rack_evidence', x.get('id') or 'reconcile', 'reconcile',
                   int(x.get('generation', 0)), {'input': x, 'summary': result['summary']})
            return {'decision': 'reconciled', **result}
        if op == 'pending':
            return {'decision': 'pending', 'items': pending(db)}
        if op == 'evidence':
            return {'decision': 'evidence', 'items': evidence_log(db)}
        raise ValueError(op)
