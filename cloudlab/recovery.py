from .store import transaction,record,audit_run

@audit_run('recovery')
def run(db,x):
    with transaction(db):
        if x['op']=='replica':
            old=db.execute('SELECT generation FROM replicas WHERE id=?',(x['id'],)).fetchone()
            if old and x['generation']<=old['generation']:return {'decision':'blocked','reason':'stale_generation'}
            db.execute('INSERT INTO replicas VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,state=excluded.state',
                       (x['id'],x['claim'],x['rack'],x['generation'],x['state']))
            record(db,'recovery',x['id'],'replica',x['generation'],x)
            return {'decision':'observed'}
        if x['op']=='snapshot':
            if x.get('parent') and not db.execute('SELECT 1 FROM snapshots WHERE id=? AND valid=1',(x['parent'],)).fetchone():
                return {'decision':'blocked','reason':'broken_chain'}
            db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?)',(x['id'],x['claim'],x.get('parent'),x['generation'],int(x.get('valid',True))))
            record(db,'recovery',x['id'],'snapshot',x['generation'],x)
            return {'decision':'stored'}
        if x['op']=='promote':
            attempt=db.execute('SELECT * FROM recovery_attempts WHERE id=?',(x['id'],)).fetchone()
            if attempt:return {'decision':'reused' if attempt['candidate']==x['candidate'] else 'blocked','reason':'attempt_conflict' if attempt['candidate']!=x['candidate'] else None}
            candidate=db.execute('SELECT * FROM replicas WHERE id=? AND claim_id=?',(x['candidate'],x['claim'])).fetchone()
            snapshot=db.execute('SELECT * FROM snapshots WHERE id=? AND claim_id=? AND valid=1',(x['snapshot'],x['claim'])).fetchone()
            binding=db.execute("SELECT * FROM bindings WHERE claim_id=? AND state='bound'",(x['claim'],)).fetchone()
            if not candidate or candidate['state']!='healthy' or not snapshot or not binding:return {'decision':'blocked','reason':'unrecoverable'}
            reservation=db.execute("SELECT * FROM reservations WHERE id=? AND state='committed'",(x.get('reservation'),)).fetchone()
            claim=db.execute('SELECT size FROM claims WHERE id=?',(x['claim'],)).fetchone()
            old_primary=db.execute("SELECT rack FROM replicas WHERE claim_id=? AND state='primary'",(x['claim'],)).fetchone()
            if not reservation or reservation['rack']!=candidate['rack'] or not claim or reservation['amount']<claim['size'] or (old_primary and old_primary['rack']==candidate['rack']):
                return {'decision':'blocked','reason':'unreserved_recovery_domain'}
            other=db.execute("SELECT claim_id FROM bindings WHERE reservation_id=? AND state IN ('bound','risk') AND claim_id!=?",(reservation['id'],x['claim'])).fetchone()
            if other:return {'decision':'blocked','reason':'recovery_capacity_in_use'}
            if candidate['generation']<snapshot['generation']:return {'decision':'blocked','reason':'stale_replica'}
            db.execute("UPDATE replicas SET state='fenced' WHERE claim_id=? AND state='primary'",(x['claim'],))
            db.execute("UPDATE replicas SET state='primary' WHERE id=?",(x['candidate'],))
            db.execute('INSERT INTO recovery_attempts VALUES(?,?,?,?,?)',(x['id'],x['claim'],x['candidate'],'promoted',candidate['generation']))
            db.execute('UPDATE bindings SET token=token+1,reservation_id=? WHERE id=?',(reservation['id'],binding['id']))
            record(db,'recovery',x['id'],'promote',candidate['generation'],x)
            return {'decision':'promoted','candidate':x['candidate'],'binding_token':binding['token']+1}
        raise ValueError(x['op'])
