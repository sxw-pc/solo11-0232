from .store import transaction,record,audit_run

@audit_run('pool')
def run(db, x):
    op=x['op']; pid=x['pool']
    with transaction(db):
        if op=='define':
            old=db.execute('SELECT version FROM pools WHERE id=?',(pid,)).fetchone()
            version=(old['version']+1) if old else 1
            used=db.execute("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? AND state IN ('reserved','committed','risk')",(pid,)).fetchone()[0]
            status='overcommitted' if used>x['capacity'] else x.get('status','healthy')
            db.execute('INSERT INTO pools VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET capacity=excluded.capacity,version=excluded.version,racks=excluded.racks,status=excluded.status',
                       (pid,x['capacity'],version,','.join(x['racks']),status))
            if status!='healthy':
                db.execute("UPDATE reservations SET state='risk',version=version+1 WHERE pool_id=? AND state='committed'",(pid,))
                db.execute("UPDATE bindings SET state='risk' WHERE reservation_id IN (SELECT id FROM reservations WHERE pool_id=? AND state='risk')",(pid,))
            record(db,'pool',pid,'define',version,x)
            return {'decision':'risk' if status!='healthy' else 'defined','version':version,'committed':used}
        pool=db.execute('SELECT * FROM pools WHERE id=?',(pid,)).fetchone()
        if not pool:return {'decision':'blocked','reason':'unknown_pool'}
        if op=='expire':
            rows=db.execute("UPDATE reservations SET state='expired',version=version+1 WHERE pool_id=? AND state='reserved' AND expires<?",(pid,x['now'])).rowcount
            record(db,'pool',pid,'expire',pool['version'],{'count':rows,'now':x['now']})
            return {'decision':'expired','count':rows}
        if op=='degrade':
            db.execute('UPDATE pools SET status=?,version=version+1 WHERE id=?',(x['status'],pid))
            db.execute("UPDATE reservations SET state='risk',version=version+1 WHERE pool_id=? AND state='committed' AND ?!='healthy'",(pid,x['status']))
            if x['status']!='healthy':
                db.execute("UPDATE bindings SET state='risk' WHERE reservation_id IN (SELECT id FROM reservations WHERE pool_id=? AND state='risk') AND state='bound'",(pid,))
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
        existing=db.execute('SELECT * FROM reservations WHERE id=?',(x['id'],)).fetchone()
        if existing:return {'decision':'reused' if existing['pool_id']==pid and existing['amount']==x['amount'] else 'blocked','reason':'id_conflict' if existing['amount']!=x['amount'] else None}
        used=db.execute("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? AND state IN ('reserved','committed','risk')",(pid,)).fetchone()[0]
        if pool['status']!='healthy':return {'decision':'blocked','reason':'pool_unhealthy'}
        if used+x['amount']>pool['capacity']:return {'decision':'blocked','reason':'insufficient_capacity'}
        if x['rack'] not in pool['racks'].split(','):return {'decision':'blocked','reason':'unknown_rack'}
        racks={r['rack'] for r in db.execute("SELECT rack FROM reservations WHERE pool_id=? AND state IN ('reserved','committed')",(pid,))}
        if x.get('independent') and x['rack'] in racks:return {'decision':'blocked','reason':'same_failure_domain'}
        db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,?,?)',(x['id'],pid,x['amount'],x['rack'],x['expires'],'reserved',1))
        record(db,'pool',x['id'],'reserve',1,x)
        return {'decision':'reserved','id':x['id']}
