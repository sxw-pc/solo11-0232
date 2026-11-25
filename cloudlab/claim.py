from .store import transaction,record,audit_run

@audit_run('claim')
def run(db,x):
    with transaction(db):
        if x['op']=='declare':
            old=db.execute('SELECT * FROM claims WHERE id=?',(x['id'],)).fetchone()
            if old:return {'decision':'reused' if old['size']==x['size'] and old['mode']==x['mode'] else 'blocked','reason':'spec_conflict' if old['size']!=x['size'] or old['mode']!=x['mode'] else None}
            db.execute('INSERT INTO claims VALUES(?,?,?,?,?)',(x['id'],x['size'],x['mode'],x['region'],1))
            record(db,'claim',x['id'],'declare',1,x)
            return {'decision':'declared'}
        if x['op']=='unbind':
            row=db.execute('SELECT * FROM bindings WHERE id=?',(x['id'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'unknown_binding'}
            db.execute("UPDATE bindings SET state='released',token=token+1 WHERE id=?",(x['id'],))
            record(db,'claim',x['id'],'unbind',row['token']+1,x)
            return {'decision':'released'}
        claim=db.execute('SELECT * FROM claims WHERE id=?',(x['claim'],)).fetchone()
        reservation=db.execute('SELECT * FROM reservations WHERE id=?',(x['reservation'],)).fetchone()
        if not claim or not reservation or reservation['state']!='committed':return {'decision':'blocked','reason':'uncommitted_capacity'}
        if claim['region']!=x['node_region'] or reservation['amount']<claim['size']:
            return {'decision':'blocked','reason':'topology_or_size'}
        old=db.execute("SELECT * FROM bindings WHERE claim_id=? AND state='bound'",(x['claim'],)).fetchone()
        if old and claim['mode']=='single_writer' and old['workload']!=x['workload']:
            return {'decision':'blocked','reason':'writer_conflict'}
        if old and old['workload']==x['workload']:return {'decision':'reused','token':old['token']}
        db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?,?)',(x['id'],x['claim'],x['reservation'],x['workload'],x['node_region'],'bound',1))
        record(db,'claim',x['id'],'bind',1,x)
        return {'decision':'bound','token':1}
