import json
from .store import transaction,record,audit_run

@audit_run('pool')
def run(db, x):
    op=x['op']; pid=x['pool']
    with transaction(db):
        if op=='define':
            if x['capacity']<0 or not x['racks']:return {'decision':'blocked','reason':'invalid_pool_capacity_or_domains'}
            old=db.execute('SELECT version FROM pools WHERE id=?',(pid,)).fetchone()
            version=(old['version']+1) if old else 1
            used=db.execute("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? AND state IN ('reserved','committed','risk')",(pid,)).fetchone()[0]
            pending=db.execute("SELECT COALESCE(SUM(p.replica_size),0) FROM placement_members m JOIN placement_plans p ON p.id=m.plan_id WHERE p.pool_id=? AND m.state='planned' AND p.state='planned'",(pid,)).fetchone()[0]
            status='overcommitted' if used+pending>x['capacity'] else x.get('status','healthy')
            regions=x.get('rack_regions',{rack:'east' for rack in x['racks']})
            if set(regions)!=set(x['racks']):return {'decision':'blocked','reason':'incomplete_rack_regions'}
            db.execute('INSERT INTO pools VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET capacity=excluded.capacity,version=excluded.version,racks=excluded.racks,rack_regions=excluded.rack_regions,status=excluded.status',
                       (pid,x['capacity'],version,','.join(x['racks']),json.dumps(regions,sort_keys=True),status))
            if status!='healthy':
                db.execute("UPDATE reservations SET state='risk',version=version+1 WHERE pool_id=? AND state='committed'",(pid,))
                db.execute("UPDATE bindings SET state='risk' WHERE reservation_id IN (SELECT id FROM reservations WHERE pool_id=? AND state='risk')",(pid,))
                db.execute("UPDATE attachments SET state='risk' WHERE binding_id IN (SELECT id FROM bindings WHERE state='risk')",())
                db.execute("UPDATE placement_plans SET state='risk' WHERE pool_id=? AND state='planned'",(pid,))
            record(db,'pool',pid,'define',version,x)
            return {'decision':'risk' if status!='healthy' else 'defined','version':version,'committed':used}
        pool=db.execute('SELECT * FROM pools WHERE id=?',(pid,)).fetchone()
        if not pool:return {'decision':'blocked','reason':'unknown_pool'}
        if op=='place':
            racks=x['racks']
            if x['replica_size']<=0:return {'decision':'blocked','reason':'invalid_replica_size'}
            existing=db.execute('SELECT * FROM placement_plans WHERE id=?',(x['id'],)).fetchone()
            if existing:
                old_racks=[r['rack'] for r in db.execute('SELECT rack FROM placement_members WHERE plan_id=? ORDER BY rack',(x['id'],))]
                return {'decision':'reused' if existing['pool_id']==pid and existing['replica_size']==x['replica_size'] and sorted(racks)==old_racks else 'blocked','reason':'plan_conflict' if existing['pool_id']!=pid or existing['replica_size']!=x['replica_size'] or sorted(racks)!=old_racks else None}
            if len(racks)<2 or len(racks)!=len(set(racks)) or not set(racks).issubset(set(pool['racks'].split(','))):
                return {'decision':'blocked','reason':'insufficient_independent_domains'}
            used=db.execute("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? AND state IN ('reserved','committed','risk')",(pid,)).fetchone()[0]
            pending=db.execute("SELECT COALESCE(SUM(p.replica_size),0) FROM placement_members m JOIN placement_plans p ON p.id=m.plan_id WHERE p.pool_id=? AND m.state='planned' AND p.state='planned'",(pid,)).fetchone()[0]
            if used+pending+x['replica_size']*len(racks)>pool['capacity']:return {'decision':'blocked','reason':'placement_capacity'}
            db.execute('INSERT INTO placement_plans VALUES(?,?,?,?)',(x['id'],pid,x['replica_size'],'planned'))
            db.executemany('INSERT INTO placement_members VALUES(?,?,?)',[(x['id'],rack,'planned') for rack in racks])
            record(db,'pool',x['id'],'place',pool['version'],x)
            return {'decision':'placed','racks':racks}
        if op=='expire':
            expired=[dict(row) for row in db.execute("SELECT id,plan_id,rack FROM reservations WHERE pool_id=? AND state='reserved' AND expires<?",(pid,x['now']))]
            rows=db.execute("UPDATE reservations SET state='expired',version=version+1 WHERE pool_id=? AND state='reserved' AND expires<?",(pid,x['now'])).rowcount
            for row in expired:
                if row['plan_id']:db.execute("UPDATE placement_members SET state='planned' WHERE plan_id=? AND rack=?",(row['plan_id'],row['rack']))
            record(db,'pool',pid,'expire',pool['version'],{'input':x,'expired_ids':[r['id'] for r in expired]})
            return {'decision':'expired','count':rows}
        if op=='degrade':
            db.execute('UPDATE pools SET status=?,version=version+1 WHERE id=?',(x['status'],pid))
            db.execute("UPDATE reservations SET state='risk',version=version+1 WHERE pool_id=? AND state='committed' AND ?!='healthy'",(pid,x['status']))
            if x['status']!='healthy':
                db.execute("UPDATE bindings SET state='risk' WHERE reservation_id IN (SELECT id FROM reservations WHERE pool_id=? AND state='risk') AND state='bound'",(pid,))
                db.execute("UPDATE attachments SET state='risk' WHERE binding_id IN (SELECT id FROM bindings WHERE state='risk')",())
            record(db,'pool',pid,'degrade',pool['version']+1,x)
            return {'decision':'risk' if x['status']!='healthy' else 'healthy'}
        if op=='commit':
            row=db.execute('SELECT * FROM reservations WHERE id=? AND pool_id=?',(x['id'],pid)).fetchone()
            if not row or row['state']!='reserved' or row['expires']<x['now']:
                return {'decision':'blocked','reason':'stale_reservation'}
            db.execute("UPDATE reservations SET state='committed',version=version+1 WHERE id=?",(x['id'],))
            record(db,'pool',x['id'],'commit',row['version']+1,x)
            return {'decision':'committed','id':x['id']}
        if op!='reserve':raise ValueError(op)
        if x['amount']<=0:return {'decision':'blocked','reason':'invalid_reservation_amount'}
        existing=db.execute('SELECT * FROM reservations WHERE id=?',(x['id'],)).fetchone()
        if existing:return {'decision':'reused' if existing['pool_id']==pid and existing['amount']==x['amount'] else 'blocked','reason':'id_conflict' if existing['amount']!=x['amount'] else None}
        used=db.execute("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? AND state IN ('reserved','committed','risk')",(pid,)).fetchone()[0]
        pending=db.execute("SELECT COALESCE(SUM(p.replica_size),0) FROM placement_members m JOIN placement_plans p ON p.id=m.plan_id WHERE p.pool_id=? AND m.state='planned' AND p.state='planned'",(pid,)).fetchone()[0]
        if pool['status']!='healthy':return {'decision':'blocked','reason':'pool_unhealthy'}
        plan_member=None
        if x.get('plan_id'):
            plan_member=db.execute("SELECT m.state,p.replica_size FROM placement_members m JOIN placement_plans p ON p.id=m.plan_id WHERE p.id=? AND p.pool_id=? AND p.state='planned' AND m.rack=?",(x['plan_id'],pid,x['rack'])).fetchone()
            if not plan_member or plan_member['state']!='planned' or plan_member['replica_size']!=x['amount']:
                return {'decision':'blocked','reason':'invalid_plan_member'}
        promised=plan_member['replica_size'] if plan_member else 0
        if used+pending+x['amount']-promised>pool['capacity']:return {'decision':'blocked','reason':'insufficient_capacity'}
        if x['rack'] not in pool['racks'].split(','):return {'decision':'blocked','reason':'unknown_rack'}
        if x.get('independent') and not x.get('plan_id'):return {'decision':'blocked','reason':'independent_requires_plan'}
        racks={r['rack'] for r in db.execute("SELECT rack FROM reservations WHERE pool_id=? AND plan_id=? AND state IN ('reserved','committed')",(pid,x.get('plan_id')))}
        if x.get('independent') and x['rack'] in racks:return {'decision':'blocked','reason':'same_failure_domain'}
        db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)',(x['id'],pid,x['amount'],x['rack'],x['expires'],'reserved',1,x.get('plan_id')))
        if x.get('plan_id'):db.execute("UPDATE placement_members SET state='reserved' WHERE plan_id=? AND rack=?",(x['plan_id'],x['rack']))
        record(db,'pool',x['id'],'reserve',1,x)
        return {'decision':'reserved','id':x['id']}
