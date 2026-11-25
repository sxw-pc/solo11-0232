"""Capture storage gateway usage and issue a provisional operation charge."""
import hashlib
import json
from .store import transaction, record


def capture_page(db, page_id, rows):
    with transaction(db):
        db.execute('CREATE TABLE IF NOT EXISTS usage_pages(id TEXT PRIMARY KEY,digest TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS usage_rows(page_id TEXT,line_no INTEGER,claim_id TEXT,period INTEGER,reads INTEGER,writes INTEGER,PRIMARY KEY(page_id,line_no))')
        if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'claim','period','reads','writes'} or min(r['period'],r['reads'],r['writes'])<0 for r in rows):
            return {'decision':'invalid_page'}
        digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        old=db.execute('SELECT digest FROM usage_pages WHERE id=?',(page_id,)).fetchone()
        if old:return {'decision':'reused' if old['digest']==digest else 'conflict'}
        db.execute('INSERT INTO usage_pages VALUES (?,?)',(page_id,digest))
        db.executemany('INSERT INTO usage_rows VALUES (?,?,?,?,?,?)',[(page_id,i,r['claim'],r['period'],r['reads'],r['writes']) for i,r in enumerate(rows,1)])
        record(db,'usage',page_id,'capture',1,{'rows':rows,'digest':digest})
        return {'decision':'captured','rows':len(rows)}


def provisional_invoice(db, invoice_id, claim_id, read_rate, write_rate):
    with transaction(db):
        db.execute('CREATE TABLE IF NOT EXISTS provisional_invoices(id TEXT PRIMARY KEY,claim_id TEXT,amount INTEGER)')
        old=db.execute('SELECT amount FROM provisional_invoices WHERE id=?',(invoice_id,)).fetchone()
        if old:return {'decision':'reused','amount':old['amount']}
        if not db.execute('SELECT id FROM claims WHERE id=?',(claim_id,)).fetchone() or min(read_rate,write_rate)<0:
            return {'decision':'unavailable'}
        amount=db.execute('SELECT COALESCE(SUM(reads*?+writes*?),0) FROM usage_rows WHERE claim_id=?',(read_rate,write_rate,claim_id)).fetchone()[0]
        db.execute('INSERT INTO provisional_invoices VALUES (?,?,?)',(invoice_id,claim_id,amount))
        record(db,'usage',invoice_id,'invoice',1,{'claim':claim_id,'amount':amount})
        return {'decision':'issued','amount':amount}
