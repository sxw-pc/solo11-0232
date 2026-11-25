"""Observed key envelopes for separate volume generations."""
from .store import transaction

def record(db,wrap_id,key_id,claim_id,snapshot_id,epoch,site,status):
    db.execute('CREATE TABLE IF NOT EXISTS key_wraps(id TEXT PRIMARY KEY,key_id TEXT,claim_id TEXT,snapshot_id TEXT,epoch INTEGER,site TEXT,status TEXT)')
    if epoch<0:return {'decision':'invalid'}
    with transaction(db):
        old=db.execute('SELECT key_id,claim_id,snapshot_id,epoch,site,status FROM key_wraps WHERE id=?',(wrap_id,)).fetchone()
        expected=(key_id,claim_id,snapshot_id,epoch,site,status)
        if old:return {'decision':'reused' if tuple(old)==expected else 'conflict'}
        db.execute('INSERT INTO key_wraps VALUES (?,?,?,?,?,?,?)',(wrap_id,*expected))
        return {'decision':'recorded'}
