"""Issue a provisional snapshot export manifest for a customer volume."""
from .store import transaction, record


def provisional_manifest(db, manifest_id, claim_id):
    with transaction(db):
        db.execute('CREATE TABLE IF NOT EXISTS export_manifests(id TEXT PRIMARY KEY,claim_id TEXT,snapshot_id TEXT,generation INTEGER)')
        old=db.execute('SELECT * FROM export_manifests WHERE id=?',(manifest_id,)).fetchone()
        if old:
            return {'decision':'reused','snapshot':old['snapshot_id']}
        if not db.execute('SELECT id FROM claims WHERE id=?',(claim_id,)).fetchone():
            return {'decision':'unavailable'}
        snapshot=db.execute('SELECT id,generation FROM snapshots WHERE claim_id=? AND valid=1 ORDER BY generation DESC LIMIT 1',(claim_id,)).fetchone()
        if not snapshot:
            return {'decision':'unavailable'}
        db.execute('INSERT INTO export_manifests VALUES (?,?,?,?)',(manifest_id,claim_id,snapshot['id'],snapshot['generation']))
        record(db,'legal_export',manifest_id,'provisional_manifest',snapshot['generation'],{'claim':claim_id,'snapshot':snapshot['id']})
        return {'decision':'issued','snapshot':snapshot['id'],'generation':snapshot['generation']}
