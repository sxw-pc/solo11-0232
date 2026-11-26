import json

from . import rack_evidence
from .store import transaction, record, audit_run


def _pool_managed_by_evidence(db, pool_id):
    """Once any alias of a pool has inventory evidence, all of it must.

    Pools that have never been inventoried keep the legacy logical-rack
    accounting; mixing the two would let an unverified alias dodge the physical
    ledger.
    """
    return any(alias[0] == pool_id for alias in rack_evidence.credential_view(db)['aliases'])


def _demand(pid):
    """Legacy ledger (still a lower bound when no inventory pages exist)."""
    return ("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? "
            "AND state IN ('reserved','committed','risk')"), \
           ("SELECT COALESCE(SUM(p.replica_size),0) FROM placement_members m "
            "JOIN placement_plans p ON p.id=m.plan_id WHERE p.pool_id=? "
            "AND m.state='planned' AND p.state IN ('planned','risk')")


@audit_run('pool')
def run(db, x):
    op = x['op']; pid = x['pool']
    with transaction(db):
        if op == 'define':
            if x['capacity'] < 0 or not x['racks']:
                return {'decision': 'blocked', 'reason': 'invalid_pool_capacity_or_domains'}
            old = db.execute('SELECT version FROM pools WHERE id=?', (pid,)).fetchone()
            version = (old['version'] + 1) if old else 1
            used = db.execute(
                "SELECT COALESCE(SUM(amount),0) FROM reservations WHERE pool_id=? "
                "AND state IN ('reserved','committed','risk')", (pid,)).fetchone()[0]
            pending = db.execute(
                "SELECT COALESCE(SUM(p.replica_size),0) FROM placement_members m "
                "JOIN placement_plans p ON p.id=m.plan_id WHERE p.pool_id=? "
                "AND m.state='planned' AND p.state IN ('planned','risk')", (pid,)).fetchone()[0]
            physical_over = [key for key, entry in rack_evidence.asset_demand(db).items()
                             if entry['has_evidence'] and entry['demand'] > entry['capacity']
                             and any(m['pool_id'] == pid for m in entry['members'])]
            status = ('overcommitted'
                      if used + pending > x['capacity'] or physical_over
                      else x.get('status', 'healthy'))
            regions = x.get('rack_regions', {rack: 'east' for rack in x['racks']})
            if set(regions) != set(x['racks']):
                return {'decision': 'blocked', 'reason': 'incomplete_rack_regions'}
            db.execute('INSERT INTO pools VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                       'capacity=excluded.capacity,version=excluded.version,racks=excluded.racks,'
                       'rack_regions=excluded.rack_regions,status=excluded.status',
                       (pid, x['capacity'], version, ','.join(x['racks']),
                        json.dumps(regions, sort_keys=True), status))
            if status != 'healthy':
                db.execute("UPDATE reservations SET state='risk',version=version+1 "
                           "WHERE pool_id=? AND state='committed'", (pid,))
                db.execute("UPDATE bindings SET state='risk' WHERE reservation_id IN "
                           "(SELECT id FROM reservations WHERE pool_id=? AND state='risk')", (pid,))
                db.execute("UPDATE attachments SET state='risk' WHERE binding_id IN "
                           "(SELECT id FROM bindings WHERE state='risk')", ())
                db.execute("UPDATE placement_plans SET state='risk' WHERE pool_id=? "
                           "AND state='planned'", (pid,))
                db.execute("UPDATE placement_members SET state='planned' WHERE plan_id IN "
                           "(SELECT id FROM placement_plans WHERE pool_id=? AND state='risk')", (pid,))
            record(db, 'pool', pid, 'define', version, x)
            return {'decision': 'risk' if status != 'healthy' else 'defined',
                    'version': version, 'committed': used}

        pool = db.execute('SELECT * FROM pools WHERE id=?', (pid,)).fetchone()
        if not pool:
            return {'decision': 'blocked', 'reason': 'unknown_pool'}

        if op == 'place':
            racks = x['racks']
            if x['replica_size'] <= 0:
                return {'decision': 'blocked', 'reason': 'invalid_replica_size'}
            existing = db.execute('SELECT * FROM placement_plans WHERE id=?', (x['id'],)).fetchone()
            if existing:
                old_racks = [r['rack'] for r in db.execute(
                    'SELECT rack FROM placement_members WHERE plan_id=? ORDER BY rack', (x['id'],))]
                same = (existing['pool_id'] == pid and existing['replica_size'] == x['replica_size']
                        and sorted(racks) == old_racks)
                return {'decision': 'reused' if same else 'blocked',
                        'reason': None if same else 'plan_conflict'}
            if len(racks) < 2 or len(racks) != len(set(racks)) or \
                    not set(racks).issubset(set(pool['racks'].split(','))):
                return {'decision': 'blocked', 'reason': 'insufficient_independent_domains'}
            # A plan needs the same effective credential for every rack it
            # names: an evidence-managed pool cannot place onto an alias whose
            # physical asset is unknown.
            if _pool_managed_by_evidence(db, pid) and \
                    not rack_evidence.evidence_backed(db, pid, racks):
                return {'decision': 'blocked', 'reason': 'rack_evidence_missing'}
            if not rack_evidence.domains_verified(db, pid, racks):
                return {'decision': 'blocked', 'reason': 'rack_evidence_unverified'}
            if not rack_evidence.distinct_domains(db, pid, racks):
                return {'decision': 'blocked', 'reason': 'same_failure_domain'}
            used = db.execute(_demand(pid)[0], (pid,)).fetchone()[0]
            planned = db.execute(_demand(pid)[1], (pid,)).fetchone()[0]
            cost = rack_evidence.placement_cost(db, pid, racks, x['replica_size'])
            if used + planned + cost > pool['capacity']:
                return {'decision': 'blocked', 'reason': 'placement_capacity'}
            if _pool_managed_by_evidence(db, pid):
                conflict = rack_evidence.planned_capacity_conflict(
                    db, pid, racks, x['replica_size'])
                if conflict:
                    return {'decision': 'blocked', 'reason': 'physical_capacity'}
            db.execute('INSERT INTO placement_plans VALUES(?,?,?,?)',
                       (x['id'], pid, x['replica_size'], 'planned'))
            db.executemany('INSERT INTO placement_members VALUES(?,?,?)',
                           [(x['id'], rack, 'planned') for rack in racks])
            rack_evidence.record_credentials_for_plan(db, x['id'], pid, racks, x['replica_size'])
            record(db, 'pool', x['id'], 'place', pool['version'], x)
            return {'decision': 'placed', 'racks': racks}

        if op == 'expire':
            expired = [dict(row) for row in db.execute(
                "SELECT id,plan_id,rack FROM reservations WHERE pool_id=? AND state='reserved' "
                "AND expires<?", (pid, x['now']))]
            rows = db.execute("UPDATE reservations SET state='expired',version=version+1 "
                              "WHERE pool_id=? AND state='reserved' AND expires<?",
                              (pid, x['now'])).rowcount
            for row in expired:
                if row['plan_id']:
                    db.execute("UPDATE placement_members SET state='planned' "
                               "WHERE plan_id=? AND rack=?", (row['plan_id'], row['rack']))
            record(db, 'pool', pid, 'expire', pool['version'],
                   {'input': x, 'expired_ids': [r['id'] for r in expired]})
            return {'decision': 'expired', 'count': rows}

        if op == 'degrade':
            db.execute('UPDATE pools SET status=?,version=version+1 WHERE id=?',
                       (x['status'], pid))
            db.execute("UPDATE reservations SET state='risk',version=version+1 "
                       "WHERE pool_id=? AND state='committed' AND ?!='healthy'",
                       (pid, x['status']))
            if x['status'] != 'healthy':
                db.execute("UPDATE bindings SET state='risk' WHERE reservation_id IN "
                           "(SELECT id FROM reservations WHERE pool_id=? AND state='risk') "
                           "AND state='bound'", (pid,))
                db.execute("UPDATE attachments SET state='risk' WHERE binding_id IN "
                           "(SELECT id FROM bindings WHERE state='risk')", ())
            record(db, 'pool', pid, 'degrade', pool['version'] + 1, x)
            return {'decision': 'risk' if x['status'] != 'healthy' else 'healthy'}

        if op == 'commit':
            row = db.execute('SELECT * FROM reservations WHERE id=? AND pool_id=?',
                             (x['id'], pid)).fetchone()
            if not row or row['state'] != 'reserved' or row['expires'] < x['now']:
                return {'decision': 'blocked', 'reason': 'stale_reservation'}
            # Re-check the physical asset at commit time too: a reservation may
            # have sat while another pool's page claimed the same cabinet.
            if _pool_managed_by_evidence(db, pid):
                conflict = rack_evidence.reservation_capacity_conflict(
                    db, pid, row['rack'], row['amount'], exclude_reservation=row['id'])
                if conflict:
                    return {'decision': 'blocked', 'reason': 'physical_capacity'}
            db.execute("UPDATE reservations SET state='committed',version=version+1 "
                       "WHERE id=?", (x['id'],))
            record(db, 'pool', x['id'], 'commit', row['version'] + 1, x)
            return {'decision': 'committed', 'id': x['id']}

        if op != 'reserve':
            raise ValueError(op)

        if x['amount'] <= 0:
            return {'decision': 'blocked', 'reason': 'invalid_reservation_amount'}
        existing = db.execute('SELECT * FROM reservations WHERE id=?', (x['id'],)).fetchone()
        if existing:
            same = existing['pool_id'] == pid and existing['amount'] == x['amount']
            return {'decision': 'reused' if same else 'blocked',
                    'reason': None if same else 'id_conflict'}
        if pool['status'] != 'healthy':
            return {'decision': 'blocked', 'reason': 'pool_unhealthy'}
        plan_member = None
        if x.get('plan_id'):
            plan_member = db.execute(
                "SELECT m.state,p.replica_size FROM placement_members m "
                "JOIN placement_plans p ON p.id=m.plan_id "
                "WHERE p.id=? AND p.pool_id=? AND p.state IN ('planned','risk') "
                "AND m.rack=?", (x['plan_id'], pid, x['rack'])).fetchone()
            if not plan_member or plan_member['state'] != 'planned' or \
                    plan_member['replica_size'] != x['amount']:
                return {'decision': 'blocked', 'reason': 'invalid_plan_member'}
            plan = db.execute('SELECT * FROM placement_plans WHERE id=?',
                              (x['plan_id'],)).fetchone()
            plan_racks = [r['rack'] for r in db.execute(
                'SELECT rack FROM placement_members WHERE plan_id=? ORDER BY rack',
                (x['plan_id'],))]
            if not rack_evidence.domains_verified(db, pid, plan_racks):
                return {'decision': 'blocked', 'reason': 'rack_evidence_unverified'}
            if not rack_evidence.distinct_domains(db, pid, plan_racks):
                return {'decision': 'blocked', 'reason': 'same_failure_domain'}
        promised = plan_member['replica_size'] if plan_member else 0
        used = db.execute(_demand(pid)[0], (pid,)).fetchone()[0]
        planned = db.execute(_demand(pid)[1], (pid,)).fetchone()[0]
        if used + planned + x['amount'] - promised > pool['capacity']:
            return {'decision': 'blocked', 'reason': 'insufficient_capacity'}
        if x['rack'] not in pool['racks'].split(','):
            return {'decision': 'blocked', 'reason': 'unknown_rack'}
        if x.get('independent') and not x.get('plan_id'):
            return {'decision': 'blocked', 'reason': 'independent_requires_plan'}
        # Independence is measured on physical power domains, not rack labels.
        if x.get('independent') and not rack_evidence.reservation_independent(
                db, pid, x['rack'], x.get('plan_id')):
            return {'decision': 'blocked', 'reason': 'same_failure_domain'}
        if _pool_managed_by_evidence(db, pid):
            # Every capacity promise in an instrumented pool must ride a real
            # inventory page; an unknown alias has no physical bytes to sell.
            if not rack_evidence.evidence_backed(db, pid, [x['rack']]):
                return {'decision': 'blocked', 'reason': 'rack_evidence_missing'}
            conflict = rack_evidence.reservation_capacity_conflict(
                db, pid, x['rack'], x['amount'], plan_size=promised)
            if conflict:
                return {'decision': 'blocked', 'reason': 'physical_capacity'}
        db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], pid, x['amount'], x['rack'], x['expires'], 'reserved', 1,
                    x.get('plan_id')))
        rack_evidence.record_credentials_for_reservation(db, x['id'], pid, x['rack'], x['amount'])
        if x.get('plan_id'):
            db.execute("UPDATE placement_members SET state='reserved' WHERE plan_id=? AND rack=?",
                       (x['plan_id'], x['rack']))
        record(db, 'pool', x['id'], 'reserve', 1, x)
        return {'decision': 'reserved', 'id': x['id']}
