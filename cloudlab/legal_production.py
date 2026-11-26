"""Court legal production workflow.

A legal production is driven by an independently identified court warrant
(调取令) and produces independently identified delivery artifacts.  It reuses
the existing claim/binding and snapshot state but never lets later writes,
unbinds, replica promotions or snapshot invalidations silently rewrite sealed
content: every delivery pins the snapshot identity, the frozen binding token,
the byte basis and the actual page hashes at seal time.

Two delivery routes are both executable under the same warrant and chosen
before sealing:

* ``sealed_page``      - whole mixed pages are sealed as ciphertext to the
                         court key; other recipients only receive page range
                         and hash proofs, never page bytes.
* ``redacted_rebuild`` - only the in-scope bytes are rebuilt into a readable
                         redacted delivery in the controlled environment and
                         handed to the court together with a sealed commitment
                         of the full pages; case agents only receive redacted
                         views, never third-party bytes.

Object lifecycle: prepared staging -> sealed artifacts -> notifications ->
receipts -> (evidence review) -> withdrawal / supplemental re-delivery.
Every stage is idempotent and replay-safe; an interrupted stage can never leave
an unauthorized readable copy (in-database staging is deleted in the same
transaction that seals, filesystem staging is 0600 and reaped by
:func:`recover_workspace`).
"""
import hashlib
import hmac
import json
import os

from .store import transaction, record


def legal_audit(fn):
    """Like store.audit_run, but the legal schema (executescript) is ensured
    outside the decision transaction because executescript auto-commits."""
    def wrapped(db, payload):
        _ensure_schema(db)
        with transaction(db):
            result = fn(db, payload)
            object_id = str(payload.get('id') or payload.get('warrant') or payload.get('delivery') or 'unknown')
            record(db, 'legal', object_id, 'decision', int(payload.get('now', payload.get('generation', 0))),
                   {'input': payload, 'result': result})
        return result
    return wrapped

PAGE_SIZE = 8
CLEARANCE_ORDER = {'confidential': 1, 'secret': 2, 'top_secret': 3}
ROUTES = ('sealed_page', 'redacted_rebuild')
OWN_SCOPE_MARK = '__claim__'


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _seal(key_hex, context, plaintext):
    """Deterministic authenticated encryption (HMAC-SHA256 keystream + MAC).

    Deterministic so a replayed event rebuilds byte-identical ciphertext.  The
    context binds the ciphertext to one artifact identity and key generation,
    so a sealed blob cannot be moved between recipients or re-used after a key
    rotation.
    """
    key = bytes.fromhex(key_hex)
    stream = b''
    counter = 0
    while len(stream) < len(plaintext):
        stream += hmac.new(key, context.encode('utf-8') + counter.to_bytes(8, 'big'), hashlib.sha256).digest()
        counter += 1
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    mac = hmac.new(key, b'lp1:' + context.encode('utf-8') + b':' + ciphertext, hashlib.sha256).digest()
    return b'LP1' + mac + ciphertext


def open_artifact(key_hex, context, blob):
    """Open a sealed artifact, authenticating its identity-bound context."""
    if not blob or blob[:3] != b'LP1' or len(blob) < 3 + 32:
        raise ValueError('bad_artifact_envelope')
    mac, ciphertext = blob[3:35], blob[35:]
    expected = hmac.new(bytes.fromhex(key_hex), b'lp1:' + context.encode('utf-8') + b':' + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError('artifact_authentication_failed')
    key = bytes.fromhex(key_hex)
    stream = b''
    counter = 0
    while len(stream) < len(ciphertext):
        stream += hmac.new(key, context.encode('utf-8') + counter.to_bytes(8, 'big'), hashlib.sha256).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


def _sign(material_hex, message):
    return hmac.new(bytes.fromhex(material_hex), message.encode('utf-8'), hashlib.sha256).hexdigest()


def _anchor(controller_id, claim_id):
    return _hash(('anchor:%s:%s' % (controller_id, claim_id)).encode('utf-8'))


def attestation_anchor(controller_id, claim_id):
    """Public anchor of a controller's continuous hash chain (for callers)."""
    return _anchor(controller_id, claim_id)


def _ensure_schema(db):
    db.executescript(
        "CREATE TABLE IF NOT EXISTS legal_controller_keys(controller_id TEXT PRIMARY KEY, material_hex TEXT, state TEXT, version INTEGER);"
        "CREATE TABLE IF NOT EXISTS legal_warrants(warrant_id TEXT PRIMARY KEY, claim_id TEXT, point_in_time INTEGER, byte_start INTEGER, byte_end INTEGER, scope_id TEXT, classification TEXT, expires_at INTEGER, request_key TEXT UNIQUE, recipients TEXT, predecessor_id TEXT, snapshot_id TEXT, binding_token INTEGER, basis_mode TEXT, state TEXT, created_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS legal_page_evidence(snapshot_id TEXT, page_no INTEGER, claim_id TEXT, data BLOB, confirmed_at INTEGER, data_hash TEXT, PRIMARY KEY(snapshot_id,page_no));"
        "CREATE TABLE IF NOT EXISTS legal_page_segments(snapshot_id TEXT, page_no INTEGER, byte_start INTEGER, byte_end INTEGER, scope_id TEXT, PRIMARY KEY(snapshot_id,page_no,byte_start,byte_end));"
        "CREATE TABLE IF NOT EXISTS legal_attestations(attestation_id TEXT PRIMARY KEY, controller_id TEXT, claim_id TEXT, point_in_time INTEGER, page_no INTEGER, snapshot_id TEXT, data_hash TEXT, prev_hash TEXT, chain_hash TEXT, signature TEXT);"
        "CREATE TABLE IF NOT EXISTS legal_recipient_keys(key_id TEXT PRIMARY KEY, recipient_id TEXT, secret_hex TEXT, clearance TEXT, state TEXT, version INTEGER, rotated_from TEXT);"
        "CREATE TABLE IF NOT EXISTS legal_deliveries(delivery_id TEXT PRIMARY KEY, warrant_id TEXT, route TEXT, basis TEXT, state TEXT, created_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS legal_artifacts(artifact_id TEXT PRIMARY KEY, delivery_id TEXT, kind TEXT, recipient_id TEXT, key_id TEXT, content BLOB, content_hash TEXT, includes_plaintext INTEGER, confidentiality TEXT);"
        "CREATE TABLE IF NOT EXISTS legal_decryption_grants(grant_id TEXT PRIMARY KEY, delivery_id TEXT, recipient_id TEXT, key_id TEXT, scope TEXT, state TEXT, version INTEGER);"
        "CREATE TABLE IF NOT EXISTS legal_notifications(notification_id TEXT PRIMARY KEY, delivery_id TEXT, recipient_id TEXT, artifact_id TEXT, state TEXT);"
        "CREATE TABLE IF NOT EXISTS legal_receipts(receipt_id TEXT PRIMARY KEY, delivery_id TEXT, recipient_id TEXT, artifact_id TEXT, receipt_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS legal_withdrawals(withdrawal_id TEXT PRIMARY KEY, delivery_id TEXT, reason TEXT, revoked_scopes TEXT, state TEXT, created_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS legal_staging(staging_id TEXT PRIMARY KEY, delivery_id TEXT, kind TEXT, plaintext BLOB, confidentiality TEXT, path TEXT);"
    )


def _page_no(offset):
    return offset // PAGE_SIZE


def _page_span(page_no):
    return page_no * PAGE_SIZE, (page_no + 1) * PAGE_SIZE


def _walk_snapshot_chain(db, snapshot_id, claim_id):
    """Return (ok, broken_snapshot_id, chain_ids)."""
    seen = set()
    current = db.execute('SELECT * FROM snapshots WHERE id=?', (snapshot_id,)).fetchone()
    expected_generation = current['generation'] if current else None
    chain = []
    while current:
        if current['id'] in seen or current['claim_id'] != claim_id or current['generation'] != expected_generation:
            return False, current['id'], chain
        seen.add(current['id'])
        chain.append(current['id'])
        if not current['valid']:
            return False, current['id'], chain
        if not current['parent']:
            return True, None, chain
        expected_generation -= 1
        current = db.execute('SELECT * FROM snapshots WHERE id=?', (current['parent'],)).fetchone()
    return False, None, chain


def _locate_snapshot(db, claim_id, point_in_time, page_nos, require_valid=True):
    """Highest generation whose requested pages were all confirmed by the point."""
    candidates = db.execute(
        'SELECT * FROM snapshots WHERE claim_id=? AND valid>=? ORDER BY generation DESC',
        (claim_id, 0 if not require_valid else 1)).fetchall()
    for snapshot in candidates:
        covered = True
        for page_no in page_nos:
            evidence = db.execute(
                'SELECT 1 FROM legal_page_evidence WHERE snapshot_id=? AND page_no=? AND confirmed_at<=?',
                (snapshot['id'], page_no, point_in_time)).fetchone()
            if not evidence:
                covered = False
                break
        if covered:
            return snapshot
    return None


def _verify_attestations(db, controller_id, claim_id, point_in_time, snapshot_id, page_nos):
    """Verify independent controller signed pages and the continuous hash chain."""
    anchor = _anchor(controller_id, claim_id)
    rows = db.execute(
        'SELECT * FROM legal_attestations WHERE controller_id=? AND claim_id=? AND point_in_time<=? ORDER BY point_in_time,page_no,attestation_id',
        (controller_id, claim_id, point_in_time)).fetchall()
    if not rows:
        return None
    key = db.execute('SELECT * FROM legal_controller_keys WHERE controller_id=?', (controller_id,)).fetchone()
    if not key or key['state'] != 'active':
        return None
    prev_hash = anchor
    per_page = {}
    for row in rows:
        message = '|'.join((row['controller_id'], row['claim_id'], str(row['point_in_time']),
                            str(row['page_no']), row['data_hash'], row['prev_hash']))
        if row['prev_hash'] != prev_hash or row['signature'] != _sign(key['material_hex'], message):
            return None
        expected_chain = _hash((prev_hash + ':' + row['data_hash']).encode('utf-8'))
        if row['chain_hash'] != expected_chain:
            return None
        prev_hash = expected_chain
        per_page[(row['point_in_time'], row['page_no'])] = row
    used = []
    for page_no in page_nos:
        match = None
        for (point, page), row in sorted(per_page.items(), reverse=True):
            if page == page_no:
                match = row
                break
        if not match:
            return None
        evidence = db.execute('SELECT data_hash FROM legal_page_evidence WHERE snapshot_id=? AND page_no=?',
                              (snapshot_id, page_no)).fetchone()
        if not evidence or evidence['data_hash'] != match['data_hash']:
            return None
        used.append(match['attestation_id'])
    return used


def _resolve_basis(db, claim_id, point_in_time, page_nos):
    """Determine the deliverable historical prefix.

    Never substitutes a newer generation for older history: only page evidence
    confirmed at or before the warrant point is eligible.  A broken ancestor is
    rescued only by independent signed attestations with a continuous hash
    chain that hash to the exact page bytes.
    """
    snapshot = _locate_snapshot(db, claim_id, point_in_time, page_nos, require_valid=True)
    if snapshot:
        ok, broken, chain = _walk_snapshot_chain(db, snapshot['id'], claim_id)
        if ok:
            return {'snapshot_id': snapshot['id'], 'generation': snapshot['generation'],
                    'basis_mode': 'full_chain', 'chain_break_at': None, 'attestations': []}
        attested = _verify_attestations(db, 'independent-controller', claim_id, point_in_time,
                                        snapshot['id'], page_nos)
        if attested:
            return {'snapshot_id': snapshot['id'], 'generation': snapshot['generation'],
                    'basis_mode': 'attested_prefix', 'chain_break_at': broken, 'attestations': attested}
        return {'blocked': 'historical_prefix_unprovable', 'snapshot_id': snapshot['id'], 'chain_break_at': broken}
    # Target snapshot itself may have been invalidated later: attestation-only rescue.
    container = _locate_snapshot(db, claim_id, point_in_time, page_nos, require_valid=False)
    if container:
        attested = _verify_attestations(db, 'independent-controller', claim_id, point_in_time,
                                        container['id'], page_nos)
        if attested:
            return {'snapshot_id': container['id'], 'generation': container['generation'],
                    'basis_mode': 'attestation_only', 'chain_break_at': container['id'],
                    'attestations': attested}
    return {'blocked': 'historical_prefix_unprovable', 'snapshot_id': None, 'chain_break_at': None}


def _segments_for(db, snapshot_id, page_no):
    """Return segments with absolute byte offsets across the whole volume."""
    base = page_no * PAGE_SIZE
    rows = db.execute(
        'SELECT * FROM legal_page_segments WHERE snapshot_id=? AND page_no=? ORDER BY byte_start',
        (snapshot_id, page_no)).fetchall()
    return [{'byte_start': base + r['byte_start'], 'byte_end': base + r['byte_end'],
             'scope_id': r['scope_id']} for r in rows]


def _gather_pages(db, basis, warrant):
    """Load and hash-check every page touching the warrant byte range."""
    page_nos = sorted({_page_no(offset) for offset in range(warrant['byte_start'], warrant['byte_end'])})
    pages = []
    own_parts = []
    foreign_pages = []
    for page_no in page_nos:
        evidence = db.execute('SELECT * FROM legal_page_evidence WHERE snapshot_id=? AND page_no=?',
                              (basis['snapshot_id'], page_no)).fetchone()
        if not evidence:
            return {'blocked': 'page_evidence_missing', 'page_no': page_no}
        if _hash(bytes(evidence['data'])) != evidence['data_hash']:
            return {'blocked': 'page_hash_mismatch', 'page_no': page_no}
        if basis['attestations']:
            attested = db.execute(
                'SELECT data_hash FROM legal_attestations WHERE claim_id=? AND page_no=? AND point_in_time<=?',
                (warrant['claim_id'], page_no, warrant['point_in_time'])).fetchall()
            if not any(row['data_hash'] == evidence['data_hash'] for row in attested):
                return {'blocked': 'attestation_hash_mismatch', 'page_no': page_no}
        data = bytes(evidence['data'])
        segments = _segments_for(db, basis['snapshot_id'], page_no)
        page_lo, page_hi = _page_span(page_no)
        cursor = page_lo
        foreign = False
        for segment in segments:
            if segment['byte_start'] != cursor or segment['byte_end'] > page_hi or segment['byte_end'] <= segment['byte_start']:
                return {'blocked': 'segment_partition_invalid', 'page_no': page_no}
            cursor = segment['byte_end']
        if cursor != page_hi or not segments:
            return {'blocked': 'segment_partition_invalid', 'page_no': page_no}
        range_lo = max(warrant['byte_start'], page_lo)
        range_hi = min(warrant['byte_end'], page_hi)
        # The whole page is a shared block as soon as it carries any foreign
        # segment anywhere - even when the warrant slice itself only covers
        # in-scope bytes.  Hidden markers alone do not discharge the boundary.
        if any(segment['scope_id'] != warrant['scope_id'] for segment in segments):
            foreign = True
        for segment in segments:
            overlap_lo = max(range_lo, segment['byte_start'])
            overlap_hi = min(range_hi, segment['byte_end'])
            if overlap_hi <= overlap_lo:
                continue
            slice_ = data[overlap_lo - page_lo:overlap_hi - page_lo]
            if segment['scope_id'] == warrant['scope_id']:
                own_parts.append(slice_)
            else:
                foreign = True
        if foreign:
            foreign_pages.append(page_no)
        pages.append({'page_no': page_no, 'data': data, 'segments': segments})
    return {'pages': pages, 'own_bytes': b''.join(own_parts), 'foreign_pages': foreign_pages, 'page_nos': page_nos}


def _active_key(db, recipient_id):
    return db.execute(
        'SELECT * FROM legal_recipient_keys WHERE recipient_id=? AND state=? ORDER BY version DESC LIMIT 1',
        (recipient_id, 'active')).fetchone()


def _check_clearance(key, classification):
    return CLEARANCE_ORDER.get(key['clearance'], 0) >= CLEARANCE_ORDER[classification]


def _staging_put(db, workspace, delivery_id, kind, blob, classification):
    staging_id = '%s:%s' % (delivery_id, kind)
    if workspace:
        folder = os.path.join(workspace, delivery_id)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, kind.replace(':', '_') + '.bin')
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, blob)
            finally:
                os.close(fd)
        db.execute('INSERT INTO legal_staging VALUES(?,?,?,?,?,?)', (staging_id, delivery_id, kind, None, classification, path))
    else:
        db.execute('INSERT INTO legal_staging VALUES(?,?,?,?,?,?)', (staging_id, delivery_id, kind, blob, classification, None))


def _staging_get(db, row):
    if row['plaintext'] is not None:
        return bytes(row['plaintext'])
    with open(row['path'], 'rb') as handle:
        return handle.read()


def _purge_staging(db, delivery_id):
    rows = db.execute('SELECT path FROM legal_staging WHERE delivery_id=?', (delivery_id,)).fetchall()
    for row in rows:
        if row['path'] and os.path.exists(row['path']):
            os.remove(row['path'])
            folder = os.path.dirname(row['path'])
            if os.path.isdir(folder) and not os.listdir(folder):
                os.rmdir(folder)
    db.execute('DELETE FROM legal_staging WHERE delivery_id=?', (delivery_id,))


def _write_staging(db, workspace, delivery_id, warrant, gathered, route):
    classification = warrant['classification']
    if route == 'sealed_page':
        for page in gathered['pages']:
            _staging_put(db, workspace, delivery_id, 'full_page:%d' % page['page_no'],
                         page['data'], classification)
        manifest = {'page_nos': gathered['page_nos'], 'foreign_pages': gathered['foreign_pages'],
                    'segments': {str(p['page_no']): p['segments'] for p in gathered['pages']}}
        _staging_put(db, workspace, delivery_id, 'manifest',
                     json.dumps(manifest, sort_keys=True).encode('utf-8'), classification)
    else:
        _staging_put(db, workspace, delivery_id, 'redacted_doc',
                     gathered['own_bytes'], classification)
        for page in gathered['pages']:
            _staging_put(db, workspace, delivery_id, 'full_page:%d' % page['page_no'],
                         page['data'], classification)
        manifest = {'page_nos': gathered['page_nos'], 'foreign_pages': gathered['foreign_pages'],
                    'redaction': 'foreign_scope_bytes_excluded',
                    'segments': {str(p['page_no']): p['segments'] for p in gathered['pages']}}
        _staging_put(db, workspace, delivery_id, 'redaction_manifest',
                     json.dumps(manifest, sort_keys=True).encode('utf-8'), classification)


def _add_artifact(db, delivery_id, kind, recipient, key, content, includes_plaintext, classification):
    artifact_id = '%s:%s:%s' % (delivery_id, recipient['id'], kind)
    context = '%s:%d' % (artifact_id, key['version'])
    sealed = _seal(key['secret_hex'], context, content)
    db.execute('INSERT OR IGNORE INTO legal_artifacts VALUES(?,?,?,?,?,?,?,?,?)',
               (artifact_id, delivery_id, kind, recipient['id'], key['key_id'], sealed,
                _hash(sealed), int(includes_plaintext), classification))
    scope = kind
    grant_id = '%s:%s:%s' % (delivery_id, recipient['id'], scope)
    db.execute('INSERT OR IGNORE INTO legal_decryption_grants VALUES(?,?,?,?,?,?,?)',
               (grant_id, delivery_id, recipient['id'], key['key_id'], scope, 'active', key['version']))
    return artifact_id


def _seal_route(db, delivery, warrant, gathered):
    recipients = json.loads(warrant['recipients'])
    route = delivery['route']
    keys = {}
    for recipient in recipients:
        key = _active_key(db, recipient['id'])
        if not key or key['state'] != 'active':
            return {'decision': 'blocked', 'reason': 'recipient_key_unavailable', 'recipient': recipient['id']}
        if not _check_clearance(key, warrant['classification']):
            return {'decision': 'blocked', 'reason': 'clearance_insufficient', 'recipient': recipient['id']}
        keys[recipient['id']] = key
    created = []
    if route == 'sealed_page':
        court = next((r for r in recipients if r.get('role') == 'court'), recipients[0])
        full = b''.join(page['data'] for page in gathered['pages'])
        created.append(_add_artifact(db, delivery['delivery_id'], 'sealed_page', court, keys[court['id']],
                                     full, False, warrant['classification']))
        proof = {'page_nos': gathered['page_nos'], 'byte_range': [warrant['byte_start'], warrant['byte_end']],
                 'page_hashes': {str(p['page_no']): _hash(p['data']) for p in gathered['pages']},
                 'foreign_pages': gathered['foreign_pages'],
                 'segments': {str(p['page_no']): p['segments'] for p in gathered['pages']},
                 'basis': json.loads(delivery['basis'])}
        for recipient in recipients:
            if recipient['id'] == court['id']:
                continue
            created.append(_add_artifact(db, delivery['delivery_id'], 'range_proof', recipient,
                                         keys[recipient['id']], json.dumps(proof, sort_keys=True).encode('utf-8'),
                                         False, warrant['classification']))
    else:
        court = next((r for r in recipients if r.get('role') == 'court'), recipients[0])
        full = b''.join(page['data'] for page in gathered['pages'])
        created.append(_add_artifact(db, delivery['delivery_id'], 'redacted_document', court,
                                     keys[court['id']], gathered['own_bytes'], True,
                                     warrant['classification']))
        created.append(_add_artifact(db, delivery['delivery_id'], 'page_commitment', court,
                                     keys[court['id']], full, False, warrant['classification']))
        redaction_view = {'in_scope_bytes_hex': gathered['own_bytes'].hex(),
                          'masked_pages': gathered['foreign_pages'],
                          'page_hashes': {str(p['page_no']): _hash(p['data']) for p in gathered['pages']},
                          'segments': {str(p['page_no']): p['segments'] for p in gathered['pages']}}
        for recipient in recipients:
            if recipient['id'] == court['id']:
                continue
            created.append(_add_artifact(db, delivery['delivery_id'], 'redacted_view', recipient,
                                         keys[recipient['id']],
                                         json.dumps(redaction_view, sort_keys=True).encode('utf-8'),
                                         True, warrant['classification']))
    _purge_staging(db, delivery['delivery_id'])
    return {'decision': 'sealed', 'delivery': delivery['delivery_id'], 'artifacts': sorted(created)}


@legal_audit
def run(db, x):
    op = x['op']
    with transaction(db):
        if op == 'register_controller_key':
            old = db.execute('SELECT * FROM legal_controller_keys WHERE controller_id=?', (x['id'],)).fetchone()
            if old:
                return {'decision': 'reused'} if old['material_hex'] == x['material_hex'] and old['state'] == x.get('state', 'active') \
                    else {'decision': 'blocked', 'reason': 'controller_key_conflict'}
            db.execute('INSERT INTO legal_controller_keys VALUES(?,?,?,?)',
                       (x['id'], x['material_hex'], x.get('state', 'active'), 1))
            return {'decision': 'registered'}

        if op == 'register_page_evidence':
            snapshot = db.execute('SELECT * FROM snapshots WHERE id=? AND claim_id=?',
                                  (x['snapshot'], x['claim'])).fetchone()
            if not snapshot:
                return {'decision': 'blocked', 'reason': 'unknown_snapshot'}
            data = bytes.fromhex(x['data_hex'])
            if len(data) > PAGE_SIZE:
                return {'decision': 'blocked', 'reason': 'page_too_large'}
            data_hash = _hash(data)
            old = db.execute('SELECT * FROM legal_page_evidence WHERE snapshot_id=? AND page_no=?',
                             (x['snapshot'], x['page_no'])).fetchone()
            if old:
                if old['data_hash'] == data_hash and old['confirmed_at'] == x['confirmed_at']:
                    return {'decision': 'reused'}
                return {'decision': 'blocked', 'reason': 'page_evidence_conflict'}
            segments = x.get('segments')
            if segments is None:
                segments = [[0, len(data), OWN_SCOPE_MARK]]
            cursor = 0
            for byte_start, byte_end, scope_id in segments:
                if byte_start != cursor or byte_end > len(data) or byte_end <= byte_start:
                    return {'decision': 'blocked', 'reason': 'segment_partition_invalid'}
                cursor = byte_end
            if cursor != len(data):
                return {'decision': 'blocked', 'reason': 'segment_partition_invalid'}
            db.execute('INSERT INTO legal_page_evidence VALUES(?,?,?,?,?,?)',
                       (x['snapshot'], x['page_no'], x['claim'], data, x['confirmed_at'], data_hash))
            db.executemany('INSERT INTO legal_page_segments VALUES(?,?,?,?,?)',
                           [(x['snapshot'], x['page_no'], s, e, scope) for s, e, scope in segments])
            record(db, 'legal', x['snapshot'], 'page_evidence', x['confirmed_at'],
                   {'page_no': x['page_no'], 'data_hash': data_hash})
            return {'decision': 'registered', 'data_hash': data_hash}

        if op == 'register_attestation':
            key = db.execute('SELECT * FROM legal_controller_keys WHERE controller_id=?', (x['controller'],)).fetchone()
            if not key or key['state'] != 'active':
                return {'decision': 'blocked', 'reason': 'unknown_controller'}
            if db.execute('SELECT 1 FROM legal_attestations WHERE attestation_id=?', (x['id'],)).fetchone():
                return {'decision': 'reused'}
            evidence = db.execute('SELECT * FROM legal_page_evidence WHERE snapshot_id=? AND page_no=?',
                                  (x['snapshot'], x['page_no'])).fetchone()
            if not evidence or evidence['data_hash'] != x['data_hash']:
                return {'decision': 'blocked', 'reason': 'attestation_hash_mismatch'}
            anchor = _anchor(x['controller'], x['claim'])
            previous = db.execute(
                'SELECT chain_hash FROM legal_attestations WHERE controller_id=? AND claim_id=? '
                'ORDER BY point_in_time,page_no,attestation_id',
                (x['controller'], x['claim'])).fetchall()
            prev_hash = previous[-1]['chain_hash'] if previous else anchor
            if x['prev_hash'] != prev_hash:
                return {'decision': 'blocked', 'reason': 'attestation_chain_broken'}
            if x['point_in_time'] <= 0:
                return {'decision': 'blocked', 'reason': 'invalid_point_in_time'}
            message = '|'.join((x['controller'], x['claim'], str(x['point_in_time']),
                                str(x['page_no']), x['data_hash'], x['prev_hash']))
            signature = _sign(key['material_hex'], message)
            if x['signature'] != signature:
                return {'decision': 'blocked', 'reason': 'attestation_signature_invalid'}
            chain_hash = _hash((prev_hash + ':' + x['data_hash']).encode('utf-8'))
            if x.get('chain_hash') and x['chain_hash'] != chain_hash:
                return {'decision': 'blocked', 'reason': 'attestation_chain_broken'}
            db.execute('INSERT INTO legal_attestations VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (x['id'], x['controller'], x['claim'], x['point_in_time'], x['page_no'], x['snapshot'],
                        x['data_hash'], prev_hash, chain_hash, signature))
            return {'decision': 'registered', 'chain_hash': chain_hash}

        if op == 'register_recipient_key':
            old = db.execute('SELECT * FROM legal_recipient_keys WHERE key_id=?', (x['id'],)).fetchone()
            if old:
                return {'decision': 'reused'} if old['recipient_id'] == x['recipient'] and old['clearance'] == x['clearance'] \
                    else {'decision': 'blocked', 'reason': 'recipient_key_conflict'}
            if x['clearance'] not in CLEARANCE_ORDER:
                return {'decision': 'blocked', 'reason': 'unknown_clearance'}
            db.execute('INSERT INTO legal_recipient_keys VALUES(?,?,?,?,?,?,?)',
                       (x['id'], x['recipient'], x['secret_hex'], x['clearance'], 'active', 1, None))
            return {'decision': 'registered'}

        if op == 'rotate_recipient_key':
            old = _active_key(db, x['recipient'])
            if not old:
                return {'decision': 'blocked', 'reason': 'unknown_recipient'}
            if db.execute('SELECT 1 FROM legal_recipient_keys WHERE key_id=?', (x['id'],)).fetchone():
                return {'decision': 'reused'}
            db.execute("UPDATE legal_recipient_keys SET state='rotated' WHERE key_id=?", (old['key_id'],))
            db.execute('INSERT INTO legal_recipient_keys VALUES(?,?,?,?,?,?,?)',
                       (x['id'], x['recipient'], x['secret_hex'], old['clearance'], 'active',
                        old['version'] + 1, old['key_id']))
            record(db, 'legal', x['recipient'], 'key_rotation', old['version'] + 1,
                   {'old_key': old['key_id'], 'new_key': x['id']})
            return {'decision': 'rotated', 'key_id': x['id'], 'version': old['version'] + 1}

        if op == 'revoke_recipient_key':
            row = db.execute('SELECT * FROM legal_recipient_keys WHERE key_id=?', (x['id'],)).fetchone()
            if not row:
                return {'decision': 'blocked', 'reason': 'unknown_key'}
            if row['state'] != 'active':
                return {'decision': 'reused'}
            db.execute("UPDATE legal_recipient_keys SET state='revoked', version=version+1 WHERE key_id=?", (x['id'],))
            return {'decision': 'revoked'}

        if op in ('freeze_warrant', 'reissue_warrant'):
            if op == 'reissue_warrant':
                predecessor = db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?', (x['predecessor'],)).fetchone()
                if not predecessor:
                    return {'decision': 'blocked', 'reason': 'unknown_predecessor_warrant'}
                if predecessor['state'] != 'withdrawn':
                    return {'decision': 'blocked', 'reason': 'predecessor_not_withdrawn'}
                payload = dict(x)
                for field in ('claim', 'point_in_time', 'byte_range', 'scope_id', 'classification',
                              'expires_at', 'recipients'):
                    payload.setdefault(field, {
                        'claim': predecessor['claim_id'],
                        'point_in_time': predecessor['point_in_time'],
                        'byte_range': [predecessor['byte_start'], predecessor['byte_end']],
                        'scope_id': predecessor['scope_id'],
                        'classification': predecessor['classification'],
                        'expires_at': x['expires_at'],
                        'recipients': json.loads(predecessor['recipients']),
                    }[field])
                x = payload
            if db.execute('SELECT 1 FROM legal_warrants WHERE request_key=?', (x['request_key'],)).fetchone():
                return {'decision': 'blocked', 'reason': 'duplicate_request'}
            existing = db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?', (x['id'],)).fetchone()
            if existing:
                return {'decision': 'reused'}
            claim_row = db.execute('SELECT * FROM claims WHERE id=?', (x['claim'],)).fetchone()
            if not claim_row:
                return {'decision': 'blocked', 'reason': 'unknown_claim'}
            byte_start, byte_end = x['byte_range']
            if byte_start < 0 or byte_end <= byte_start:
                return {'decision': 'blocked', 'reason': 'invalid_byte_range'}
            if x['point_in_time'] < 0:
                return {'decision': 'blocked', 'reason': 'invalid_point_in_time'}
            if x['classification'] not in CLEARANCE_ORDER or x['expires_at'] <= x['now']:
                return {'decision': 'blocked', 'reason': 'invalid_warrant_terms'}
            recipients = x['recipients']
            if not recipients or any('id' not in r or 'clearance' not in r for r in recipients):
                return {'decision': 'blocked', 'reason': 'invalid_recipients'}
            if any(CLEARANCE_ORDER.get(r['clearance'], 0) < CLEARANCE_ORDER[x['classification']] for r in recipients):
                return {'decision': 'blocked', 'reason': 'recipient_clearance_below_warrant'}
            binding = db.execute("SELECT * FROM bindings WHERE claim_id=? AND state='bound'", (x['claim'],)).fetchone()
            binding_token = binding['token'] if binding else None
            predecessor_id = x.get('predecessor') if op == 'reissue_warrant' else None
            db.execute('INSERT INTO legal_warrants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (x['id'], x['claim'], x['point_in_time'], byte_start, byte_end, x['scope_id'],
                        x['classification'], x['expires_at'], x['request_key'],
                        json.dumps(recipients, sort_keys=True), predecessor_id, None, binding_token,
                        None, 'frozen', x['now']))
            record(db, 'legal', x['id'], 'warrant_frozen', x['now'],
                   {'claim': x['claim'], 'point_in_time': x['point_in_time'],
                    'byte_range': [byte_start, byte_end], 'predecessor': predecessor_id})
            return {'decision': 'frozen', 'warrant': x['id'], 'binding_token': binding_token}

        if op == 'prepare_delivery':
            warrant = db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?', (x['warrant'],)).fetchone()
            if not warrant:
                return {'decision': 'blocked', 'reason': 'unknown_warrant'}
            if x['route'] not in ROUTES:
                return {'decision': 'blocked', 'reason': 'unknown_route'}
            if warrant['state'] != 'frozen':
                return {'decision': 'blocked', 'reason': 'warrant_not_frozen'}
            if x['now'] > warrant['expires_at']:
                return {'decision': 'blocked', 'reason': 'warrant_expired'}
            active = db.execute(
                "SELECT * FROM legal_deliveries WHERE warrant_id=? AND route=? AND state!='aborted'",
                (x['warrant'], x['route'])).fetchone()
            if active:
                return {'decision': 'reused', 'delivery': active['delivery_id'], 'state': active['state']}
            old = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['id'],)).fetchone()
            if old:
                return {'decision': 'blocked', 'reason': 'delivery_id_conflict'}
            page_nos = sorted({_page_no(offset)
                               for offset in range(warrant['byte_start'], warrant['byte_end'])})
            basis = _resolve_basis(db, warrant['claim_id'], warrant['point_in_time'], page_nos)
            if 'blocked' in basis:
                return {'decision': 'blocked', 'reason': basis['blocked']}
            gathered = _gather_pages(db, basis, warrant)
            if 'blocked' in gathered:
                return {'decision': 'blocked', 'reason': gathered['blocked']}
            db.execute('INSERT INTO legal_deliveries VALUES(?,?,?,?,?,?)',
                       (x['id'], x['warrant'], x['route'], json.dumps(basis, sort_keys=True),
                        'prepared', x['now']))
            db.execute('UPDATE legal_warrants SET snapshot_id=?, basis_mode=? WHERE warrant_id=?',
                       (basis['snapshot_id'], basis['basis_mode'], x['warrant']))
            _write_staging(db, x.get('workspace'), x['id'], warrant, gathered, x['route'])
            if x.get('_fail_after_staging'):
                # Simulated crash: the evidence transaction rolls back, but any
                # filesystem staging material (0600) survives and must be reaped
                # before a retry can produce a readable copy.
                raise RuntimeError('simulated crash after staging')
            record(db, 'legal', x['id'], 'delivery_prepared', x['now'],
                   {'warrant': x['warrant'], 'route': x['route'], 'basis': basis,
                    'foreign_pages': gathered['foreign_pages']})
            return {'decision': 'prepared', 'delivery': x['id'], 'basis': basis,
                    'foreign_pages': gathered['foreign_pages']}

        if op == 'abort_delivery':
            delivery = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['id'],)).fetchone()
            if not delivery:
                return {'decision': 'blocked', 'reason': 'unknown_delivery'}
            if delivery['state'] != 'prepared':
                return {'decision': 'reused', 'state': delivery['state']}
            _purge_staging(db, x['id'])
            db.execute("UPDATE legal_deliveries SET state='aborted' WHERE delivery_id=?", (x['id'],))
            return {'decision': 'aborted', 'delivery': x['id']}

        if op == 'seal_delivery':
            delivery = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['id'],)).fetchone()
            if not delivery:
                return {'decision': 'blocked', 'reason': 'unknown_delivery'}
            if delivery['state'] in ('sealed', 'notified', 'receipted', 'impaired', 'withdrawn'):
                artifacts = [r['artifact_id'] for r in db.execute(
                    'SELECT artifact_id FROM legal_artifacts WHERE delivery_id=? ORDER BY artifact_id',
                    (x['id'],)).fetchall()]
                return {'decision': 'reused', 'delivery': x['id'], 'state': delivery['state'],
                        'artifacts': artifacts}
            if delivery['state'] != 'prepared':
                return {'decision': 'blocked', 'reason': 'delivery_not_prepared'}
            warrant = db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?',
                                 (delivery['warrant_id'],)).fetchone()
            if x['now'] > warrant['expires_at']:
                return {'decision': 'blocked', 'reason': 'warrant_expired'}
            page_nos = sorted({_page_no(offset)
                               for offset in range(warrant['byte_start'], warrant['byte_end'])})
            basis = json.loads(delivery['basis'])
            gathered = _gather_pages(db, basis, warrant)
            if 'blocked' in gathered:
                return {'decision': 'blocked', 'reason': gathered['blocked']}
            # Re-stage automatically if a crash removed staging files/rows.
            if not db.execute('SELECT 1 FROM legal_staging WHERE delivery_id=?', (x['id'],)).fetchone():
                _write_staging(db, x.get('workspace'), x['id'], warrant, gathered, delivery['route'])
            result = _seal_route(db, delivery, warrant, gathered)
            if result.get('decision') == 'blocked':
                return result
            db.execute("UPDATE legal_deliveries SET state='sealed' WHERE delivery_id=?", (x['id'],))
            record(db, 'legal', x['id'], 'delivery_sealed', x['now'],
                   {'warrant': delivery['warrant_id'], 'route': delivery['route'], 'artifacts': result['artifacts']})
            return result

        if op == 'notify_delivery':
            delivery = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['id'],)).fetchone()
            if not delivery:
                return {'decision': 'blocked', 'reason': 'unknown_delivery'}
            if delivery['state'] == 'prepared':
                return {'decision': 'blocked', 'reason': 'delivery_not_sealed'}
            if delivery['state'] in ('notified', 'receipted', 'impaired', 'withdrawn'):
                existing = db.execute(
                    'SELECT notification_id FROM legal_notifications WHERE delivery_id=? ORDER BY notification_id',
                    (x['id'],)).fetchall()
                return {'decision': 'reused', 'notifications': [row['notification_id'] for row in existing]}
            artifacts = db.execute('SELECT * FROM legal_artifacts WHERE delivery_id=?', (x['id'],)).fetchall()
            sent = []
            for artifact in artifacts:
                notification_id = '%s:%s:%s' % (x['id'], artifact['recipient_id'], artifact['kind'])
                db.execute('INSERT OR IGNORE INTO legal_notifications VALUES(?,?,?,?,?)',
                           (notification_id, x['id'], artifact['recipient_id'], artifact['artifact_id'], 'sent'))
                sent.append(notification_id)
            db.execute("UPDATE legal_deliveries SET state='notified' WHERE delivery_id=?", (x['id'],))
            record(db, 'legal', x['id'], 'delivery_notified', x['now'], {'notifications': sorted(sent)})
            return {'decision': 'notified', 'notifications': sorted(sent)}

        if op == 'ack_receipt':
            delivery = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['delivery'],)).fetchone()
            if not delivery:
                return {'decision': 'blocked', 'reason': 'unknown_delivery'}
            artifact = db.execute('SELECT * FROM legal_artifacts WHERE artifact_id=?', (x['artifact'],)).fetchone()
            if not artifact or artifact['delivery_id'] != x['delivery'] or artifact['recipient_id'] != x['recipient']:
                return {'decision': 'blocked', 'reason': 'artifact_not_for_recipient'}
            if db.execute('SELECT 1 FROM legal_receipts WHERE receipt_id=?', (x['id'],)).fetchone():
                return {'decision': 'reused'}
            db.execute('INSERT INTO legal_receipts VALUES(?,?,?,?,?)',
                       (x['id'], x['delivery'], x['recipient'], x['artifact'], x['now']))
            pending = db.execute(
                'SELECT a.artifact_id FROM legal_artifacts a WHERE a.delivery_id=? AND NOT EXISTS('
                'SELECT 1 FROM legal_receipts r WHERE r.artifact_id=a.artifact_id)', (x['delivery'],)).fetchall()
            state = 'receipted' if not pending else delivery['state']
            db.execute('UPDATE legal_deliveries SET state=? WHERE delivery_id=?', (state, x['delivery']))
            record(db, 'legal', x['id'], 'receipt', x['now'],
                   {'delivery': x['delivery'], 'recipient': x['recipient'], 'artifact': x['artifact']})
            return {'decision': 'receipted' if state == 'receipted' else 'partially_receipted'}

        if op == 'review_evidence':
            delivery = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['id'],)).fetchone()
            if not delivery:
                return {'decision': 'blocked', 'reason': 'unknown_delivery'}
            warrant = db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?',
                                 (delivery['warrant_id'],)).fetchone()
            page_nos = sorted({_page_no(offset)
                               for offset in range(warrant['byte_start'], warrant['byte_end'])})
            current = _resolve_basis(db, warrant['claim_id'], warrant['point_in_time'], page_nos)
            sealed_basis = json.loads(delivery['basis'])
            if 'blocked' in current:
                verdict = 'compromised'
            elif current['basis_mode'] == 'full_chain' and current['snapshot_id'] == sealed_basis['snapshot_id']:
                verdict = 'sound'
            else:
                verdict = 'impaired'
            if verdict in ('impaired', 'compromised') and delivery['state'] not in ('withdrawn', 'aborted'):
                db.execute('UPDATE legal_deliveries SET state=? WHERE delivery_id=?',
                           ('impaired' if verdict == 'impaired' else 'compromised', x['id']))
            record(db, 'legal', x['id'], 'evidence_review', x['now'],
                   {'delivery': x['id'], 'verdict': verdict, 'current_basis': current})
            return {'decision': verdict, 'sealed_basis': sealed_basis, 'current_basis': current}

        if op == 'withdraw_delivery':
            delivery = db.execute('SELECT * FROM legal_deliveries WHERE delivery_id=?', (x['id'],)).fetchone()
            if not delivery:
                return {'decision': 'blocked', 'reason': 'unknown_delivery'}
            if delivery['state'] == 'withdrawn':
                return {'decision': 'reused'}
            if delivery['state'] not in ('receipted', 'impaired', 'compromised', 'notified'):
                return {'decision': 'blocked', 'reason': 'delivery_not_in_force'}
            if delivery['route'] == 'sealed_page':
                scopes = ['sealed_page', 'range_proof']
            else:
                scopes = ['page_commitment']
            placeholders = ','.join('?' for _ in scopes)
            grants = db.execute(
                'SELECT grant_id FROM legal_decryption_grants WHERE delivery_id=? AND scope IN (%s)' % placeholders,
                (x['id'], *scopes)).fetchall()
            for grant in grants:
                db.execute("UPDATE legal_decryption_grants SET state='revoked', version=version+1 WHERE grant_id=?",
                           (grant['grant_id'],))
            db.execute('INSERT INTO legal_withdrawals VALUES(?,?,?,?,?,?)',
                       (x['withdrawal_id'], x['id'], x['reason'], json.dumps(scopes), 'withdrawn', x['now']))
            db.execute("UPDATE legal_deliveries SET state='withdrawn' WHERE delivery_id=?", (x['id'],))
            db.execute("UPDATE legal_warrants SET state='withdrawn' WHERE warrant_id=?",
                       (delivery['warrant_id'],))
            record(db, 'legal', x['withdrawal_id'], 'delivery_withdrawn', x['now'],
                   {'delivery': x['id'], 'reason': x['reason'], 'revoked_scopes': scopes})
            return {'decision': 'withdrawn', 'delivery': x['id'], 'revoked_scopes': scopes}

        raise ValueError(op)


def recover_workspace(db, root):
    """Reap staging plaintext left by a crashed preparation.

    Orphan folders are shredded, and in-database staging rows whose delivery
    no longer exists or is no longer in the prepared state are purged.  Never
    touches sealed artifacts, receipts or withdrawal records.
    """
    _ensure_schema(db)
    reaped = []
    if os.path.isdir(root):
        for name in os.listdir(root):
            folder = os.path.join(root, name)
            row = db.execute('SELECT state FROM legal_deliveries WHERE delivery_id=?', (name,)).fetchone()
            if not row or row['state'] != 'prepared':
                for entry in os.listdir(folder):
                    os.remove(os.path.join(folder, entry))
                os.rmdir(folder)
                reaped.append(folder)
    with transaction(db):
        orphans = db.execute(
            'SELECT s.staging_id,s.path FROM legal_staging s JOIN legal_deliveries d ON d.delivery_id=s.delivery_id '
            "WHERE d.state!='prepared'").fetchall()
        for row in orphans:
            if row['path'] and os.path.exists(row['path']):
                os.remove(row['path'])
            db.execute('DELETE FROM legal_staging WHERE staging_id=?', (row['staging_id'],))
    return {'reaped_folders': sorted(reaped), 'reaped_rows': len(orphans)}
