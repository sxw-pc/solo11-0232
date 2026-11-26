import json
from . import rack_evidence
from .store import transaction,record,audit_run

def valid_chain(db, snapshot, claim_id):
    seen=set(); expected=snapshot['generation']
    current=snapshot
    while current:
        if current['id'] in seen or not current['valid'] or current['claim_id']!=claim_id or current['generation']!=expected:
            return False
        seen.add(current['id'])
        if not current['parent']:return True
        expected-=1
        current=db.execute('SELECT * FROM snapshots WHERE id=?',(current['parent'],)).fetchone()
    return False

@audit_run('recovery')
def run(db,x):
    with transaction(db):
        if x['op']=='replica':
            old=db.execute('SELECT * FROM replicas WHERE id=?',(x['id'],)).fetchone()
            if old and (old['claim_id']!=x['claim'] or old['rack']!=x['rack']):return {'decision':'blocked','reason':'replica_identity_conflict'}
            if old and x['generation']<=old['generation']:return {'decision':'blocked','reason':'stale_generation'}
            db.execute('INSERT INTO replicas VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,state=excluded.state',
                       (x['id'],x['claim'],x['rack'],x['generation'],x['state']))
            record(db,'recovery',x['id'],'replica',x['generation'],x)
            return {'decision':'observed'}
        if x['op']=='invalidate_snapshot':
            row=db.execute('SELECT * FROM snapshots WHERE id=?',(x['id'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'unknown_snapshot'}
            db.execute('UPDATE snapshots SET valid=0 WHERE id=?',(x['id'],))
            record(db,'recovery',x['id'],'invalidate_snapshot',row['generation'],x)
            return {'decision':'invalidated'}
        if x['op']=='fence':
            primary=db.execute("SELECT * FROM replicas WHERE id=? AND claim_id=? AND state='primary'",(x['primary'],x['claim'])).fetchone()
            if not primary:return {'decision':'blocked','reason':'no_active_primary'}
            binding=db.execute("SELECT * FROM bindings WHERE claim_id=? AND state='bound'",(x['claim'],)).fetchone()
            if not binding:return {'decision':'blocked','reason':'no_active_binding'}
            db.execute("UPDATE replicas SET state='fenced' WHERE id=?",(x['primary'],))
            db.execute('INSERT INTO fences VALUES(?,?,?,?,?)',(x['id'],x['claim'],x['primary'],primary['generation'],'active'))
            db.execute("UPDATE writer_grants SET state='revoked',generation=generation+1 WHERE binding_id=? AND state='active'",(binding['id'],))
            db.execute("UPDATE attachments SET state='fenced' WHERE binding_id=? AND state='attached'",(binding['id'],))
            record(db,'recovery',x['id'],'fence',primary['generation'],x)
            return {'decision':'fenced','primary':x['primary']}
        if x['op']=='snapshot':
            if not db.execute('SELECT 1 FROM claims WHERE id=?',(x['claim'],)).fetchone():
                return {'decision':'blocked','reason':'unknown_claim'}
            if x.get('parent'):
                parent=db.execute('SELECT * FROM snapshots WHERE id=? AND valid=1',(x['parent'],)).fetchone()
                if not parent or not valid_chain(db,parent,x['claim']) or x['generation']!=parent['generation']+1:
                    return {'decision':'blocked','reason':'broken_chain'}
            db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?)',(x['id'],x['claim'],x.get('parent'),x['generation'],int(x.get('valid',True))))
            record(db,'recovery',x['id'],'snapshot',x['generation'],x)
            return {'decision':'stored'}
        if x['op']=='plan_restore':
            candidate=db.execute('SELECT * FROM replicas WHERE id=? AND claim_id=?',(x['candidate'],x['claim'])).fetchone()
            snapshot=db.execute('SELECT * FROM snapshots WHERE id=? AND claim_id=?',(x['snapshot'],x['claim'])).fetchone()
            if not candidate or candidate['state']!='healthy' or not snapshot or not valid_chain(db,snapshot,x['claim']) or candidate['generation']<snapshot['generation']:
                return {'decision':'blocked','reason':'restore_evidence_incomplete'}
            db.execute('INSERT INTO restore_plans VALUES(?,?,?,?,?)',(x['id'],x['claim'],x['candidate'],x['snapshot'],'ready'))
            record(db,'recovery',x['id'],'plan_restore',snapshot['generation'],x)
            return {'decision':'restorable','snapshot':x['snapshot']}
        if x['op']=='promote':
            attempt=db.execute('SELECT * FROM recovery_attempts WHERE id=?',(x['id'],)).fetchone()
            if attempt:return {'decision':'reused' if attempt['candidate']==x['candidate'] else 'blocked','reason':'attempt_conflict' if attempt['candidate']!=x['candidate'] else None}
            candidate=db.execute('SELECT * FROM replicas WHERE id=? AND claim_id=?',(x['candidate'],x['claim'])).fetchone()
            snapshot=db.execute('SELECT * FROM snapshots WHERE id=? AND claim_id=? AND valid=1',(x['snapshot'],x['claim'])).fetchone()
            binding=db.execute("SELECT * FROM bindings WHERE claim_id=? AND state='bound'",(x['claim'],)).fetchone()
            if not candidate or candidate['state']!='healthy' or not snapshot or not binding:return {'decision':'blocked','reason':'unrecoverable'}
            if not valid_chain(db,snapshot,x['claim']):return {'decision':'blocked','reason':'broken_chain'}
            fence=db.execute("SELECT * FROM fences WHERE id=? AND claim_id=? AND state='active'",(x.get('fence'),x['claim'])).fetchone()
            plan=db.execute("SELECT * FROM restore_plans WHERE id=? AND claim_id=? AND candidate=? AND snapshot_id=? AND state='ready'",(x.get('restore_plan'),x['claim'],x['candidate'],x['snapshot'])).fetchone()
            if not fence or not plan:return {'decision':'blocked','reason':'missing_fence_or_restore_plan'}
            latest_fence=db.execute('SELECT MAX(generation) FROM fences WHERE claim_id=?',(x['claim'],)).fetchone()[0]
            if fence['generation']!=latest_fence:return {'decision':'blocked','reason':'stale_fence'}
            reservation=db.execute("SELECT * FROM reservations WHERE id=? AND state='committed'",(x.get('reservation'),)).fetchone()
            claim=db.execute('SELECT size,region FROM claims WHERE id=?',(x['claim'],)).fetchone()
            old_primary=db.execute("SELECT rack FROM replicas WHERE claim_id=? AND state='primary'",(x['claim'],)).fetchone()
            if not reservation or reservation['rack']!=candidate['rack'] or not claim or reservation['amount']<claim['size'] or (old_primary and old_primary['rack']==candidate['rack']):
                return {'decision':'blocked','reason':'unreserved_recovery_domain'}
            pool=db.execute('SELECT rack_regions FROM pools WHERE id=?',(reservation['pool_id'],)).fetchone()
            if not pool or json.loads(pool['rack_regions']).get(reservation['rack'])!=claim['region']:
                return {'decision':'blocked','reason':'recovery_topology_mismatch'}
            if not rack_evidence.recovery_credential_ok(db,reservation['id'],candidate['rack']):
                return {'decision':'blocked','reason':'recovery_credential_mismatch'}
            if not rack_evidence.recovery_domain_ok(db,x['claim'],candidate['id'],candidate['rack']):
                return {'decision':'blocked','reason':'same_failure_domain'}
            if old_primary:return {'decision':'blocked','reason':'active_primary_after_fence'}
            other=db.execute("SELECT claim_id FROM bindings WHERE reservation_id=? AND state IN ('bound','risk') AND claim_id!=?",(reservation['id'],x['claim'])).fetchone()
            if other:return {'decision':'blocked','reason':'recovery_capacity_in_use'}
            if candidate['generation']<snapshot['generation']:return {'decision':'blocked','reason':'stale_replica'}
            db.execute("UPDATE replicas SET state='primary' WHERE id=?",(x['candidate'],))
            db.execute("UPDATE fences SET state='consumed' WHERE id=?",(x['fence'],))
            db.execute("UPDATE restore_plans SET state='consumed' WHERE id=?",(x['restore_plan'],))
            db.execute('INSERT INTO recovery_attempts VALUES(?,?,?,?,?)',(x['id'],x['claim'],x['candidate'],'promoted',candidate['generation']))
            db.execute('UPDATE bindings SET token=token+1,reservation_id=? WHERE id=?',(reservation['id'],binding['id']))
            rack_evidence.record_credential(db,'binding',binding['id'],reservation['pool_id'],reservation['rack'])
            db.execute("UPDATE writer_grants SET state='revoked',generation=generation+1 WHERE binding_id=? AND state='active'",(binding['id'],))
            db.execute("UPDATE attachments SET state='fenced' WHERE binding_id=? AND state='attached'",(binding['id'],))
            record(db,'recovery',x['id'],'promote',candidate['generation'],x)
            return {'decision':'promoted','candidate':x['candidate'],'binding_token':binding['token']+1}
        raise ValueError(x['op'])
