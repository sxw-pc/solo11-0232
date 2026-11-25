import json
from .store import transaction,record,audit_run

@audit_run('claim')
def run(db,x):
    with transaction(db):
        if x['op']=='declare':
            old=db.execute('SELECT * FROM claims WHERE id=?',(x['id'],)).fetchone()
            if old:return {'decision':'reused' if old['size']==x['size'] and old['mode']==x['mode'] and old['region']==x['region'] else 'blocked','reason':'spec_conflict' if old['size']!=x['size'] or old['mode']!=x['mode'] or old['region']!=x['region'] else None}
            db.execute('INSERT INTO claims VALUES(?,?,?,?,?)',(x['id'],x['size'],x['mode'],x['region'],1))
            record(db,'claim',x['id'],'declare',1,x)
            return {'decision':'declared'}
        if x['op']=='unbind':
            row=db.execute('SELECT * FROM bindings WHERE id=?',(x['id'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'unknown_binding'}
            db.execute("UPDATE bindings SET state='released',token=token+1 WHERE id=?",(x['id'],))
            db.execute("UPDATE writer_grants SET state='revoked',generation=generation+1 WHERE binding_id=? AND state='active'",(x['id'],))
            db.execute("UPDATE attachments SET state='detached' WHERE binding_id=? AND state='attached'",(x['id'],))
            record(db,'claim',x['id'],'unbind',row['token']+1,x)
            return {'decision':'released'}
        if x['op']=='grant':
            binding=db.execute("SELECT * FROM bindings WHERE id=? AND state='bound'",(x['binding'],)).fetchone()
            if not binding or binding['workload']!=x['workload']:return {'decision':'blocked','reason':'unbound_writer'}
            claim=db.execute('SELECT mode FROM claims WHERE id=?',(binding['claim_id'],)).fetchone()
            if claim['mode']!='single_writer':return {'decision':'blocked','reason':'grant_not_required'}
            active=db.execute("SELECT * FROM writer_grants WHERE claim_id=? AND state='active'",(binding['claim_id'],)).fetchone()
            if active:return {'decision':'reused' if active['workload']==x['workload'] else 'blocked','reason':'writer_occupied' if active['workload']!=x['workload'] else None}
            db.execute('INSERT INTO writer_grants VALUES(?,?,?,?,?,?)',(x['id'],binding['claim_id'],x['binding'],x['workload'],'active',1))
            record(db,'claim',x['id'],'grant',1,x)
            return {'decision':'granted'}
        if x['op']=='attach':
            binding=db.execute("SELECT * FROM bindings WHERE id=? AND state='bound'",(x['binding'],)).fetchone()
            if not binding or binding['node_region']!=x['node_region']:
                return {'decision':'blocked','reason':'binding_topology'}
            claim=db.execute('SELECT mode FROM claims WHERE id=?',(binding['claim_id'],)).fetchone()
            if claim['mode']=='single_writer' and not db.execute("SELECT 1 FROM writer_grants WHERE binding_id=? AND state='active'",(x['binding'],)).fetchone():
                return {'decision':'blocked','reason':'missing_writer_grant'}
            old=db.execute('SELECT * FROM attachments WHERE id=?',(x['id'],)).fetchone()
            if old:return {'decision':'reused' if old['binding_id']==x['binding'] and old['token']==binding['token'] else 'blocked','reason':'attachment_conflict' if old['binding_id']!=x['binding'] or old['token']!=binding['token'] else None}
            db.execute('INSERT INTO attachments VALUES(?,?,?,?,?)',(x['id'],x['binding'],x['node_region'],binding['token'],'attached'))
            record(db,'claim',x['id'],'attach',binding['token'],x)
            return {'decision':'attached','token':binding['token']}
        claim=db.execute('SELECT * FROM claims WHERE id=?',(x['claim'],)).fetchone()
        reservation=db.execute('SELECT * FROM reservations WHERE id=?',(x['reservation'],)).fetchone()
        if not claim or not reservation or reservation['state']!='committed':return {'decision':'blocked','reason':'uncommitted_capacity'}
        pool=db.execute('SELECT rack_regions FROM pools WHERE id=?',(reservation['pool_id'],)).fetchone()
        coverage=json.loads(pool['rack_regions']).get(reservation['rack']) if pool else None
        if claim['region']!=x['node_region'] or coverage!=x['node_region'] or reservation['amount']<claim['size']:
            return {'decision':'blocked','reason':'topology_or_size'}
        occupied=db.execute("SELECT claim_id,workload FROM bindings WHERE reservation_id=? AND state IN ('bound','risk')",(x['reservation'],)).fetchone()
        if occupied:return {'decision':'blocked','reason':'writer_conflict' if occupied['claim_id']==x['claim'] and occupied['workload']!=x['workload'] else 'reservation_in_use'}
        old=db.execute("SELECT * FROM bindings WHERE claim_id=? AND state='bound'",(x['claim'],)).fetchone()
        if old and claim['mode']=='single_writer' and old['workload']!=x['workload']:
            return {'decision':'blocked','reason':'writer_conflict'}
        if old and old['workload']==x['workload']:return {'decision':'reused','token':old['token']}
        db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?,?)',(x['id'],x['claim'],x['reservation'],x['workload'],x['node_region'],'bound',1))
        record(db,'claim',x['id'],'bind',1,x)
        return {'decision':'bound','token':1}
