"""A successful decrypt probe proves only the tested copy and moment."""
from .store import transaction

def result(db,probe_id,claim_id,snapshot_id,key_id,site,at,outcome):
    db.execute('CREATE TABLE IF NOT EXISTS decrypt_probes(id TEXT PRIMARY KEY,claim_id TEXT,snapshot_id TEXT,key_id TEXT,site TEXT,at INTEGER,outcome TEXT)')
    if at<0:return {'decision':'invalid'}
    with transaction(db):
        old=db.execute('SELECT claim_id,snapshot_id,key_id,site,at,outcome FROM decrypt_probes WHERE id=?',(probe_id,)).fetchone()
        expected=(claim_id,snapshot_id,key_id,site,at,outcome)
        if old:return {'decision':'reused' if tuple(old)==expected else 'conflict'}
        db.execute('INSERT INTO decrypt_probes VALUES (?,?,?,?,?,?,?)',(probe_id,*expected))
        return {'decision':'recorded'}
