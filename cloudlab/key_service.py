"""Key-service receipts are independent of snapshot decryptability."""
from .store import transaction

def receipt(db,receipt_id,key_id,action,at,site,result):
    db.execute('CREATE TABLE IF NOT EXISTS key_receipts(id TEXT PRIMARY KEY,key_id TEXT,action TEXT,at INTEGER,site TEXT,result TEXT)')
    if at<0:return {'decision':'invalid'}
    with transaction(db):
        old=db.execute('SELECT key_id,action,at,site,result FROM key_receipts WHERE id=?',(receipt_id,)).fetchone()
        expected=(key_id,action,at,site,result)
        if old:return {'decision':'reused' if tuple(old)==expected else 'conflict'}
        db.execute('INSERT INTO key_receipts VALUES (?,?,?,?,?,?)',(receipt_id,*expected))
        return {'decision':'recorded'}
