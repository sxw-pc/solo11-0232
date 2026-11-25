import tempfile
import unittest
from pathlib import Path
import cloudlab
from cloudlab.store import connect,report,replay
from cloudlab import pool,claim,recovery

class Workflows(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.db=connect(str(Path(self.tmp.name)/'x.sqlite'))
    def tearDown(self): self.db.close();self.tmp.cleanup()
    def base(self):
        pool.run(self.db,dict(op='define',pool='p',capacity=100,racks=['a','b']))
        pool.run(self.db,dict(op='place',pool='p',id='plan',replica_size=30,racks=['a','b']))
        pool.run(self.db,dict(op='reserve',pool='p',id='r',amount=30,rack='a',expires=100,independent=True))
        pool.run(self.db,dict(op='commit',pool='p',id='r',now=10))
        pool.run(self.db,dict(op='reserve',pool='p',id='r2',amount=30,rack='b',expires=100,independent=True))
        pool.run(self.db,dict(op='commit',pool='p',id='r2',now=10))
        claim.run(self.db,dict(op='declare',id='c',size=20,mode='single_writer',region='east'))
        claim.run(self.db,dict(op='bind',id='b',claim='c',reservation='r',workload='app',node_region='east'))
    def test_capacity_domain_and_expiration(self):
        pool.run(self.db,dict(op='define',pool='p',capacity=40,racks=['a','b']))
        self.assertEqual(pool.run(self.db,dict(op='reserve',pool='p',id='r',amount=30,rack='a',expires=5,independent=True))['decision'],'reserved')
        self.assertEqual(pool.run(self.db,dict(op='reserve',pool='p',id='r2',amount=20,rack='b',expires=30,independent=True))['reason'],'insufficient_capacity')
        self.assertEqual(pool.run(self.db,dict(op='expire',pool='p',now=10))['count'],1)
        self.assertEqual(pool.run(self.db,dict(op='commit',pool='p',id='r',now=10))['reason'],'stale_reservation')
    def test_claim_conflict_and_topology(self):
        self.base()
        self.assertEqual(claim.run(self.db,dict(op='bind',id='b2',claim='c',reservation='r',workload='other',node_region='east'))['reason'],'writer_conflict')
        self.assertEqual(claim.run(self.db,dict(op='bind',id='b3',claim='c',reservation='r',workload='other',node_region='west'))['reason'],'topology_or_size')
        self.assertEqual(claim.run(self.db,dict(op='attach',id='a',binding='b',node_region='east'))['reason'],'missing_writer_grant')
        self.assertEqual(claim.run(self.db,dict(op='grant',id='g',binding='b',workload='app'))['decision'],'granted')
        self.assertEqual(claim.run(self.db,dict(op='attach',id='a',binding='b',node_region='west'))['reason'],'binding_topology')
        self.assertEqual(claim.run(self.db,dict(op='attach',id='a',binding='b',node_region='east'))['decision'],'attached')
    def test_recovery_fencing_and_retry(self):
        self.base()
        claim.run(self.db,dict(op='grant',id='g',binding='b',workload='app'))
        claim.run(self.db,dict(op='attach',id='a1',binding='b',node_region='east'))
        recovery.run(self.db,dict(op='replica',id='old',claim='c',rack='a',generation=1,state='primary'))
        recovery.run(self.db,dict(op='replica',id='new',claim='c',rack='b',generation=2,state='healthy'))
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='bad',claim='c',parent='missing',generation=2))['reason'],'broken_chain')
        recovery.run(self.db,dict(op='snapshot',id='s',claim='c',generation=1,valid=True))
        self.assertEqual(recovery.run(self.db,dict(op='plan_restore',id='rp',claim='c',candidate='new',snapshot='s'))['decision'],'restorable')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2'))['reason'],'missing_fence_or_restore_plan')
        self.assertEqual(recovery.run(self.db,dict(op='fence',id='f',claim='c',primary='old'))['decision'],'fenced')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2',fence='f',restore_plan='rp'))['decision'],'promoted')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2',fence='f',restore_plan='rp'))['decision'],'reused')
        self.assertEqual(self.db.execute("SELECT state FROM replicas WHERE id='old'").fetchone()[0],'fenced')
        self.assertEqual(self.db.execute("SELECT state FROM attachments WHERE id='a1'").fetchone()[0],'fenced')
        self.assertEqual(self.db.execute("SELECT state FROM writer_grants WHERE id='g'").fetchone()[0],'revoked')
        self.assertTrue(any(x['event']=='promote' for x in report(self.db)))

    def test_evidence_replays_full_rejection_and_state(self):
        self.base()
        pool.run(self.db,dict(op='reserve',pool='p',id='x',amount=200,rack='b',expires=100))
        result=replay(str(Path(self.tmp.name)/'x.sqlite'),{'pool':pool,'claim':claim,'recovery':recovery})
        self.assertTrue(result['verified'],result['divergences'])
        self.assertGreater(result['decision_count'],5)
    def test_capacity_shrink_marks_bound_claim_at_risk(self):
        self.base()
        self.assertEqual(pool.run(self.db,dict(op='define',pool='p',capacity=40,racks=['a','b']))['decision'],'risk')
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='b'").fetchone()[0],'risk')
    def test_rack_independence_and_pool_risk_propagation(self):
        self.base()
        self.assertEqual(pool.run(self.db,dict(op='place',pool='p',id='bad-plan',replica_size=10,racks=['a','a']))['reason'],'insufficient_independent_domains')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM placement_members WHERE plan_id='plan'").fetchone()[0],2)
        self.assertEqual(pool.run(self.db,dict(op='reserve',pool='p',id='same',amount=10,rack='a',expires=100,independent=True))['reason'],'same_failure_domain')
        self.assertEqual(pool.run(self.db,dict(op='degrade',pool='p',status='degraded'))['decision'],'risk')
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='b'").fetchone()[0],'risk')
        self.assertEqual(self.db.execute("SELECT state FROM reservations WHERE id='r'").fetchone()[0],'risk')
    def test_claim_identity_and_release(self):
        self.base()
        self.assertEqual(claim.run(self.db,dict(op='declare',id='c',size=25,mode='single_writer',region='east'))['reason'],'spec_conflict')
        self.assertEqual(claim.run(self.db,dict(op='declare',id='c',size=20,mode='single_writer',region='west'))['reason'],'spec_conflict')
        claim.run(self.db,dict(op='declare',id='other',size=10,mode='single_writer',region='east'))
        self.assertEqual(claim.run(self.db,dict(op='bind',id='taken',claim='other',reservation='r',workload='other',node_region='east'))['reason'],'reservation_in_use')
        self.assertEqual(claim.run(self.db,dict(op='unbind',id='b'))['decision'],'released')
        self.assertEqual(claim.run(self.db,dict(op='bind',id='b2',claim='c',reservation='r',workload='other',node_region='east'))['decision'],'bound')
    def test_recovery_requires_committed_capacity_in_candidate_domain(self):
        self.base()
        recovery.run(self.db,dict(op='replica',id='old',claim='c',rack='a',generation=1,state='primary'))
        recovery.run(self.db,dict(op='replica',id='new',claim='c',rack='b',generation=2,state='healthy'))
        recovery.run(self.db,dict(op='snapshot',id='s',claim='c',generation=1,valid=True))
        recovery.run(self.db,dict(op='plan_restore',id='rp',claim='c',candidate='new',snapshot='s'))
        recovery.run(self.db,dict(op='fence',id='f',claim='c',primary='old'))
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r',fence='f',restore_plan='rp'))['reason'],'unreserved_recovery_domain')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2',fence='f',restore_plan='rp'))['decision'],'promoted')
        self.assertEqual(self.db.execute("SELECT reservation_id FROM bindings WHERE id='b'").fetchone()[0],'r2')
    def test_replica_generation_and_snapshot_parent(self):
        self.base()
        recovery.run(self.db,dict(op='replica',id='rep',claim='c',rack='b',generation=2,state='healthy'))
        self.assertEqual(recovery.run(self.db,dict(op='replica',id='rep',claim='c',rack='b',generation=1,state='primary'))['reason'],'stale_generation')
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='child',claim='c',parent='missing',generation=2))['reason'],'broken_chain')
    def test_snapshot_chain_rejects_cross_claim_skip_and_lost_ancestor(self):
        self.base()
        claim.run(self.db,dict(op='declare',id='c2',size=10,mode='single_writer',region='east'))
        recovery.run(self.db,dict(op='snapshot',id='root',claim='c',generation=1,valid=True))
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='cross',claim='c2',parent='root',generation=2,valid=True))['reason'],'broken_chain')
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='skip',claim='c',parent='root',generation=3,valid=True))['reason'],'broken_chain')
        recovery.run(self.db,dict(op='snapshot',id='child',claim='c',parent='root',generation=2,valid=True))
        recovery.run(self.db,dict(op='replica',id='new',claim='c',rack='b',generation=3,state='healthy'))
        recovery.run(self.db,dict(op='invalidate_snapshot',id='root'))
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='grandchild',claim='c',parent='child',generation=3,valid=True))['reason'],'broken_chain')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='child',reservation='r2'))['reason'],'broken_chain')

assert Path(cloudlab.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1])
print('imported_module_file=',cloudlab.__file__)
if __name__=='__main__':unittest.main()
