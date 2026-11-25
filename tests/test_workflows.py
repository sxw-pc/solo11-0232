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
    def test_recovery_fencing_and_retry(self):
        self.base()
        recovery.run(self.db,dict(op='replica',id='old',claim='c',rack='a',generation=1,state='primary'))
        recovery.run(self.db,dict(op='replica',id='new',claim='c',rack='b',generation=2,state='healthy'))
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='bad',claim='c',parent='missing',generation=2))['reason'],'broken_chain')
        recovery.run(self.db,dict(op='snapshot',id='s',claim='c',generation=1,valid=True))
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2'))['decision'],'promoted')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2'))['decision'],'reused')
        self.assertEqual(self.db.execute("SELECT state FROM replicas WHERE id='old'").fetchone()[0],'fenced')
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
        recovery.run(self.db,dict(op='replica',id='new',claim='c',rack='b',generation=2,state='healthy'))
        recovery.run(self.db,dict(op='snapshot',id='s',claim='c',generation=1,valid=True))
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r'))['reason'],'unreserved_recovery_domain')
        self.assertEqual(recovery.run(self.db,dict(op='promote',id='a',claim='c',candidate='new',snapshot='s',reservation='r2'))['decision'],'promoted')
        self.assertEqual(self.db.execute("SELECT reservation_id FROM bindings WHERE id='b'").fetchone()[0],'r2')
    def test_replica_generation_and_snapshot_parent(self):
        self.base()
        recovery.run(self.db,dict(op='replica',id='rep',claim='c',rack='b',generation=2,state='healthy'))
        self.assertEqual(recovery.run(self.db,dict(op='replica',id='rep',claim='c',rack='b',generation=1,state='primary'))['reason'],'stale_generation')
        self.assertEqual(recovery.run(self.db,dict(op='snapshot',id='child',claim='c',parent='missing',generation=2))['reason'],'broken_chain')

print('imported_module_file=',cloudlab.__file__)
if __name__=='__main__':unittest.main()
