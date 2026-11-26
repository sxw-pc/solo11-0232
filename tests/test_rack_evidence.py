"""Physical rack evidence: credentials, shared cabinets, remediation, replay.

The tests drive the public entry points (``rack_evidence``, ``pool``, ``claim``,
``recovery``) so the credential model is exercised through the same paths an
operator uses.
"""

import json
import tempfile
import unittest
from pathlib import Path

import cloudlab
from cloudlab import claim, pool, rack_evidence, recovery
from cloudlab.store import connect, report, replay


def _pages(**overrides):
    return dict(overrides)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'x.sqlite')
        self.db = connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------
    def observe(self, **page):
        return rack_evidence.run(self.db, dict(op='observe', **page))

    def two_pools(self):
        pool.run(self.db, dict(op='define', pool='A', capacity=16,
                               racks=['rack-a', 'spare-a']))
        pool.run(self.db, dict(op='define', pool='B', capacity=16,
                               racks=['rack-b', 'rack-c']))

    def unverified_inventory(self):
        # Controller N1 reports into A/rack-a, N2 into B/rack-b.  Nameplates
        # (cabinets) are not yet verified.
        self.observe(evidence_version='inv-0', pool='A', rack='rack-a',
                     controller='N1', backplane='BP-1', capacity=8, observed_at=1)
        self.observe(evidence_version='inv-0', pool='B', rack='rack-b',
                     controller='N2', backplane='BP-2', capacity=8, observed_at=1)

    def volume_v(self):
        """Volume V: 6 units committed in A/rack-a, written by W."""
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='A', id='v', amount=6,
                                                rack='rack-a', expires=100))['decision'], 'reserved')
        pool.run(self.db, dict(op='commit', pool='A', id='v', now=1))
        claim.run(self.db, dict(op='declare', id='V', size=6, mode='single_writer', region='east'))
        self.assertEqual(claim.run(self.db, dict(op='bind', id='bV', claim='V', reservation='v',
                                                 workload='W', node_region='east'))['decision'], 'bound')
        claim.run(self.db, dict(op='grant', id='gV', binding='bV', workload='W'))
        claim.run(self.db, dict(op='attach', id='aV', binding='bV', node_region='east'))

    def standby_for_v(self, rack='spare-a'):
        result = pool.run(self.db, dict(op='reserve', pool='A', id='v-stby', amount=6,
                                        rack=rack, expires=100))
        if result['decision'] == 'reserved':
            pool.run(self.db, dict(op='commit', pool='A', id='v-stby', now=1))
        return result

    def verified_pages(self, same_cabinet):
        cab_b = 'C1' if same_cabinet else 'C9'
        cab_c = 'C1' if same_cabinet else 'C4'
        self.observe(evidence_version='inv-1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=2)
        self.observe(evidence_version='inv-1', pool='B', rack='rack-b', controller='N2',
                     cabinet=cab_b, capacity=8, verified=True, observed_at=2)
        self.observe(evidence_version='inv-1', pool='A', rack='spare-a', controller='N3',
                     cabinet='C2', capacity=8, verified=True, observed_at=2)
        self.observe(evidence_version='inv-1', pool='B', rack='rack-c', controller='N4',
                     cabinet=cab_c, capacity=8, verified=True, observed_at=2)


class IdentityTests(Base):
    def test_same_cabinet_under_two_controllers_is_one_asset(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', serial='S1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', serial='S2', capacity=8, verified=True, observed_at=1)
        view = rack_evidence.credential_view(self.db)
        key_a = view['aliases'][('A', 'rack-a')]['physical_key']
        key_b = view['aliases'][('B', 'rack-b')]['physical_key']
        self.assertEqual(key_a, key_b)
        self.assertEqual(view['aliases'][('A', 'rack-a')]['domain_key'],
                         view['aliases'][('B', 'rack-b')]['domain_key'])
        self.assertEqual(len(view['assets']), 1)

    def test_controller_renumber_does_not_create_a_new_cabinet(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', serial='S1', capacity=8, verified=True, observed_at=1)
        # Same cabinet; controller renumbered N1 -> N9 on a later page.
        self.observe(evidence_version='p2', pool='A', rack='rack-a', controller='N9',
                     cabinet='C1', serial='S1', capacity=8, verified=True, observed_at=2)
        view = rack_evidence.credential_view(self.db)
        self.assertEqual(view['aliases'][('A', 'rack-a')]['physical_key'], 'cabinet:c1')
        self.assertEqual(view['aliases'][('A', 'rack-a')]['evidence_version'], 'p2')

    def test_distinct_cabinets_with_the_same_rack_name_stay_distinct(self):
        # Two pools both call their enclosure "rack-a" but they are two assets.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-a', controller='N2',
                     cabinet='C2', capacity=8, verified=True, observed_at=1)
        view = rack_evidence.credential_view(self.db)
        self.assertNotEqual(view['aliases'][('A', 'rack-a')]['physical_key'],
                            view['aliases'][('B', 'rack-a')]['physical_key'])
        self.assertEqual(len(view['assets']), 2)

    def test_evidence_version_and_identity_are_recorded(self):
        self.observe(evidence_version='inv-9', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', backplane='BP', serial='S', capacity=8,
                     verified=True, observed_at=1)
        row = self.db.execute("SELECT * FROM rack_evidence").fetchone()
        self.assertEqual(row['evidence_version'], 'inv-9')
        self.assertEqual(row['state'], 'applied')
        credential = self.db.execute(
            "SELECT * FROM capacity_credentials WHERE kind='reservation'").fetchone()
        self.assertIsNone(credential)  # no reservation yet

    def test_shared_cabinet_capacity_is_not_summed_across_controllers(self):
        # Two controller pages for one cabinet must not add up to 16.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        view = rack_evidence.credential_view(self.db)
        self.assertEqual(view['assets']['cabinet:c1']['capacity'], 8)

    def test_repair_page_lowers_the_shared_asset_not_raises_it(self):
        # Controller N1 later sees the repaired cabinet with fewer usable bytes;
        # the other controller's older page must not mask the shrink.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p3', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=3, verified=True, observed_at=2)
        view = rack_evidence.credential_view(self.db)
        self.assertEqual(view['assets']['cabinet:c1']['capacity'], 3)


class SharedCapacityTests(Base):
    def test_same_bytes_cannot_be_sold_to_two_pools(self):
        # Both aliases resolve to the same 8-unit cabinet.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='A', id='a1', amount=6,
                                                rack='rack-a', expires=100))['decision'], 'reserved')
        result = pool.run(self.db, dict(op='reserve', pool='B', id='b1', amount=6,
                                        rack='rack-b', expires=100))
        self.assertEqual(result['reason'], 'physical_capacity')

    def test_two_controller_pages_are_not_summed_into_one_pool(self):
        # N1 and N2 both report the same cabinet with 8 bytes each.  A naive
        # pool_id + rack aggregation would see 16 and sell 12 to U.
        self.observe(evidence_version='p1', pool='B', rack='rack-b', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-c', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        placed = pool.run(self.db, dict(op='place', pool='B', id='u-plan', replica_size=6,
                                        racks=['rack-b', 'rack-c']))
        self.assertEqual(placed['reason'], 'same_failure_domain')

    def test_planned_members_hold_capacity_across_pools(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='A', rack='spare-a', controller='N3',
                     cabinet='C2', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p3', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        self.assertEqual(pool.run(self.db, dict(op='place', pool='A', id='a-plan',
                                                replica_size=6,
                                                racks=['rack-a', 'spare-a']))['decision'],
                         'placed')
        # The unmaterialised plan member alone occupies the shared cabinet.
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='b1', amount=6,
                                                rack='rack-b', expires=100))['reason'],
                         'physical_capacity')

    def test_expiry_releases_physical_capacity(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        pool.run(self.db, dict(op='reserve', pool='A', id='a1', amount=6,
                               rack='rack-a', expires=10))
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='b1', amount=6,
                                                rack='rack-b', expires=100))['reason'],
                         'physical_capacity')
        self.assertEqual(pool.run(self.db, dict(op='expire', pool='A', now=20))['count'], 1)
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='b1', amount=6,
                                                rack='rack-b', expires=100))['decision'],
                         'reserved')

    def test_expiry_does_not_steal_capacity_back_from_recovery(self):
        # A standby reservation for V uses the shared cabinet; once it expires
        # the bytes are free, but a concurrent commit of the other pool's
        # reservation must not double count them.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        pool.run(self.db, dict(op='reserve', pool='A', id='a1', amount=6,
                               rack='rack-a', expires=10))
        self.assertEqual(pool.run(self.db, dict(op='commit', pool='B', id='missing', now=1))['reason'],
                         'stale_reservation')
        self.assertEqual(pool.run(self.db, dict(op='expire', pool='A', now=20))['count'], 1)
        # Now B may take the freed bytes exactly once.
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='b1', amount=8,
                                                rack='rack-b', expires=100))['decision'],
                         'reserved')
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='b2', amount=1,
                                                rack='rack-b', expires=100))['reason'],
                         'physical_capacity')

    def test_commit_rechecks_shared_asset(self):
        # Reservations are made against 8-byte unverified pages, then the
        # verified nameplate says the shared cabinet only holds 6 bytes.
        self.observe(evidence_version='p0', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, observed_at=1)
        self.observe(evidence_version='p0b', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, observed_at=1)
        self.two_pools()
        pool.run(self.db, dict(op='reserve', pool='A', id='a1', amount=4,
                               rack='rack-a', expires=100))
        pool.run(self.db, dict(op='reserve', pool='B', id='b1', amount=4,
                               rack='rack-b', expires=100))
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=6, verified=True, observed_at=2)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=6, verified=True, observed_at=2)
        self.assertEqual(pool.run(self.db, dict(op='commit', pool='A', id='a1', now=1))['reason'],
                         'physical_capacity')
        self.assertEqual(pool.run(self.db, dict(op='commit', pool='B', id='b1', now=1))['reason'],
                         'physical_capacity')


class DomainIndependenceTests(Base):
    def test_two_unverified_pages_cannot_prove_two_domains(self):
        self.unverified_inventory()
        self.observe(evidence_version='inv-0', pool='B', rack='rack-c', controller='N4',
                     backplane='BP-4', capacity=8, observed_at=1)
        self.two_pools()
        result = pool.run(self.db, dict(op='place', pool='B', id='u-plan', replica_size=6,
                                        racks=['rack-b', 'rack-c']))
        self.assertEqual(result['reason'], 'rack_evidence_unverified')

    def test_shared_cabinet_is_not_an_independent_failure_domain(self):
        self.unverified_inventory()
        self.two_pools()
        self.verified_pages(same_cabinet=True)
        self.assertEqual(pool.run(self.db, dict(op='place', pool='B', id='u-plan',
                                                replica_size=6, racks=['rack-b', 'rack-c']))['reason'],
                         'same_failure_domain')
        # A lone reserve that does not claim independence is allowed, but U's
        # two-replica plan has already been refused as sharing one cabinet.
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM placement_plans WHERE id='u-plan'").fetchone()[0], 0)

    def test_rack_alias_does_not_launder_a_shared_domain(self):
        # N1 in A/rack-a and N9 in B/rack-b are the same cabinet, different
        # rack names.  A plan naming both aliases must still see one domain.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N9',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.observe(evidence_version='p3', pool='B', rack='rack-c', controller='N4',
                     cabinet='C4', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        pool.run(self.db, dict(op='reserve', pool='A', id='a1', amount=2,
                               rack='rack-a', expires=100))
        self.assertEqual(pool.run(self.db, dict(op='place', pool='B', id='p', replica_size=2,
                                                racks=['rack-b', 'rack-c']))['decision'],
                         'placed')
        # The plan itself cannot locate both replicas on one cabinet.
        self.assertEqual(pool.run(self.db, dict(op='place', pool='B', id='p2', replica_size=2,
                                                racks=['rack-b', 'rack-a']))['reason'],
                         'insufficient_independent_domains')


class AcceptanceScenarioTests(Base):
    """The two operator-acceptable outcomes start from the same unverified pages."""

    def _prepare(self):
        self.unverified_inventory()
        self.two_pools()
        self.volume_v()

    def test_same_cabinet_protects_v_rejects_u_and_re_places_recovery(self):
        self._prepare()
        # Before nameplates, U must not be pre-sold rack-b as independent.
        self.assertEqual(pool.run(self.db, dict(op='place', pool='B', id='u-plan',
                                                replica_size=3, racks=['rack-b', 'rack-c']))['reason'],
                         'rack_evidence_missing')
        self.verified_pages(same_cabinet=True)
        self.assertEqual(pool.run(self.db, dict(op='place', pool='B', id='u-plan',
                                                replica_size=3, racks=['rack-b', 'rack-c']))['reason'],
                         'same_failure_domain')
        # V keeps its committed 6 units and its writer's binding.
        self.assertEqual(self.db.execute("SELECT state FROM reservations WHERE id='v'").fetchone()[0],
                         'committed')
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='bV'").fetchone()[0],
                         'bound')
        self.assertEqual(self.db.execute("SELECT state FROM attachments WHERE id='aV'").fetchone()[0],
                         'attached')
        self.assertEqual(self.db.execute("SELECT state FROM writer_grants WHERE id='gV'").fetchone()[0],
                         'active')
        # V's recovery needs another physical cabinet: spare-a (C2) works.
        self.assertEqual(self.standby_for_v()['decision'], 'reserved')
        recovery.run(self.db, dict(op='replica', id='oldV', claim='V', rack='rack-a',
                                   generation=1, state='primary'))
        recovery.run(self.db, dict(op='replica', id='newV', claim='V', rack='spare-a',
                                   generation=2, state='healthy'))
        recovery.run(self.db, dict(op='snapshot', id='sV', claim='V', generation=1, valid=True))
        self.assertEqual(recovery.run(self.db, dict(op='plan_restore', id='rpV', claim='V',
                                                    candidate='newV', snapshot='sV'))['decision'],
                         'restorable')
        recovery.run(self.db, dict(op='fence', id='fV', claim='V', primary='oldV'))
        self.assertEqual(recovery.run(self.db, dict(op='promote', id='aV2', claim='V',
                                                    candidate='newV', snapshot='sV',
                                                    reservation='v-stby', fence='fV',
                                                    restore_plan='rpV'))['decision'],
                         'promoted')

    def test_distinct_cabinets_sells_u_while_v_keeps_standby(self):
        self._prepare()
        self.verified_pages(same_cabinet=False)
        self.assertEqual(pool.run(self.db, dict(op='place', pool='B', id='u-plan',
                                                replica_size=3, racks=['rack-b', 'rack-c']))['decision'],
                         'placed')
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='u-b', amount=3,
                                                rack='rack-b', expires=100, plan_id='u-plan',
                                                independent=True))['decision'], 'reserved')
        self.assertEqual(pool.run(self.db, dict(op='reserve', pool='B', id='u-c', amount=3,
                                                rack='rack-c', expires=100, plan_id='u-plan',
                                                independent=True))['decision'], 'reserved')
        self.assertEqual(pool.run(self.db, dict(op='commit', pool='B', id='u-b', now=1))['decision'],
                         'committed')
        # V remains untouched and keeps its recovery path.
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='bV'").fetchone()[0],
                         'bound')
        self.assertEqual(self.standby_for_v()['decision'], 'reserved')
        self.assertEqual(self.db.execute("SELECT state FROM reservations WHERE id='v-stby'").fetchone()[0],
                         'committed')

    def test_outcomes_differ_on_the_same_unverified_start(self):
        # Same starting pages; the supplementary page flips the answer.
        self._prepare()
        self.verified_pages(same_cabinet=True)
        shared = pool.run(self.db, dict(op='place', pool='B', id='u-plan', replica_size=3,
                                        racks=['rack-b', 'rack-c']))['decision']

        self.db.close()
        self.db = connect(str(Path(self.tmp.name) / 'other.sqlite'))
        self._prepare()
        self.verified_pages(same_cabinet=False)
        distinct = pool.run(self.db, dict(op='place', pool='B', id='u-plan', replica_size=3,
                                          racks=['rack-b', 'rack-c']))['decision']
        self.assertEqual(shared, 'blocked')
        self.assertEqual(distinct, 'placed')


class ReconcileTests(Base):
    def _overbooked(self):
        # V: 6 units on C1 in A.  U: standby 6 units on the *same* C1 under a
        # different alias in B.  The alias arrives via a late page.
        self.unverified_inventory()
        self.two_pools()
        self.volume_v()
        pool.run(self.db, dict(op='reserve', pool='A', id='v-stby', amount=6,
                               rack='spare-a', expires=100))
        pool.run(self.db, dict(op='commit', pool='A', id='v-stby', now=1))
        pool.run(self.db, dict(op='reserve', pool='B', id='u-standby', amount=6,
                               rack='rack-b', expires=100))
        pool.run(self.db, dict(op='commit', pool='B', id='u-standby', now=1))
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=2)
        self.observe(evidence_version='p1', pool='A', rack='spare-a', controller='N3',
                     cabinet='C2', capacity=8, verified=True, observed_at=2)
        self.observe(evidence_version='p2', pool='B', rack='rack-b', controller='N2',
                     cabinet='C1', capacity=8, verified=True, observed_at=2)

    def test_overbooking_keeps_customer_volume_and_lists_standby(self):
        self._overbooked()
        result = rack_evidence.run(self.db, dict(op='reconcile', id='rec', require_evidence=True))
        self.assertEqual(result['decision'], 'reconciled')
        ids = {(r['kind'], r['object_id'], r['protected']) for r in result['pending']}
        self.assertIn(('reservation', 'v', True), ids)
        self.assertIn(('reservation', 'u-standby', False), ids)
        # V's writer keeps writing; the standby is risked, not detached.
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='bV'").fetchone()[0],
                         'bound')
        self.assertEqual(self.db.execute("SELECT state FROM reservations WHERE id='v'").fetchone()[0],
                         'committed')
        self.assertEqual(self.db.execute("SELECT state FROM reservations WHERE id='u-standby'").fetchone()[0],
                         'risk')

    def test_reconcile_is_bounded_and_idempotent(self):
        self._overbooked()
        first = rack_evidence.run(self.db, dict(op='reconcile', id='r1'))
        second = rack_evidence.run(self.db, dict(op='reconcile', id='r2'))
        self.assertEqual(len(first['pending']), len(second['pending']))
        self.assertEqual([(r['kind'], r['object_id']) for r in first['pending']],
                         [(r['kind'], r['object_id']) for r in second['pending']])

    def test_reconcile_never_detaches_all_volumes(self):
        self._overbooked()
        rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        # The valid volume V is untouched; a wholesale unbind is not acceptable.
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM bindings WHERE state='bound'").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM bindings WHERE state='released'").fetchone()[0], 0)

    def test_binding_survives_when_only_its_own_bytes_are_supported(self):
        # The shared cabinet is overbooked, but V's own 6 bytes are still
        # covered by the page; V must keep writing and the standby is listed.
        self._overbooked()
        result = rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        v_rows = [r for r in result['pending'] if r['object_id'] == 'v']
        self.assertTrue(v_rows and all(r['protected'] for r in v_rows))
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='bV'").fetchone()[0],
                         'bound')

    def test_recovery_promotion_is_blocked_when_candidate_reuses_live_domain(self):
        self.unverified_inventory()
        self.two_pools()
        self.volume_v()
        # Both aliases turn out to name the same power cabinet C1, but it has
        # enough bytes (16) for both V and a correctly sized standby.
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=16, verified=True, observed_at=1)
        self.observe(evidence_version='p2', pool='A', rack='spare-a', controller='N3',
                     cabinet='C1', capacity=16, verified=True, observed_at=1)
        pool.run(self.db, dict(op='reserve', pool='A', id='v-stby', amount=6,
                               rack='spare-a', expires=100))
        pool.run(self.db, dict(op='commit', pool='A', id='v-stby', now=1))
        recovery.run(self.db, dict(op='replica', id='oldV', claim='V', rack='rack-a',
                                   generation=1, state='primary'))
        recovery.run(self.db, dict(op='replica', id='newV', claim='V', rack='spare-a',
                                   generation=2, state='healthy'))
        recovery.run(self.db, dict(op='snapshot', id='sV', claim='V', generation=1, valid=True))
        recovery.run(self.db, dict(op='plan_restore', id='rpV', claim='V',
                                   candidate='newV', snapshot='sV'))
        recovery.run(self.db, dict(op='fence', id='fV', claim='V', primary='oldV'))
        # The ledger has enough bytes, but the candidate shares C1 with the
        # fenced primary, so it is not a recovery domain.
        self.assertEqual(recovery.run(self.db, dict(op='promote', id='aV2', claim='V',
                                                    candidate='newV', snapshot='sV',
                                                    reservation='v-stby', fence='fV',
                                                    restore_plan='rpV'))['reason'],
                         'same_failure_domain')

    def test_recovery_promotion_and_new_u_reservation_do_not_share_bytes(self):
        self.unverified_inventory()
        self.two_pools()
        self.volume_v()
        self.verified_pages(same_cabinet=False)
        pool.run(self.db, dict(op='reserve', pool='A', id='v-stby', amount=6,
                               rack='spare-a', expires=100))
        pool.run(self.db, dict(op='commit', pool='A', id='v-stby', now=1))
        recovery.run(self.db, dict(op='replica', id='oldV', claim='V', rack='rack-a',
                                   generation=1, state='primary'))
        recovery.run(self.db, dict(op='replica', id='newV', claim='V', rack='spare-a',
                                   generation=2, state='healthy'))
        recovery.run(self.db, dict(op='snapshot', id='sV', claim='V', generation=1, valid=True))
        recovery.run(self.db, dict(op='plan_restore', id='rpV', claim='V',
                                   candidate='newV', snapshot='sV'))
        recovery.run(self.db, dict(op='fence', id='fV', claim='V', primary='oldV'))
        # U takes B's bytes on separate cabinets while V promotes on A's spare.
        pool.run(self.db, dict(op='place', pool='B', id='u-plan', replica_size=3,
                               racks=['rack-b', 'rack-c']))
        pool.run(self.db, dict(op='reserve', pool='B', id='u-b', amount=3, rack='rack-b',
                               expires=100, plan_id='u-plan', independent=True))
        pool.run(self.db, dict(op='reserve', pool='B', id='u-c', amount=3, rack='rack-c',
                               expires=100, plan_id='u-plan', independent=True))
        self.assertEqual(recovery.run(self.db, dict(op='promote', id='aV2', claim='V',
                                                    candidate='newV', snapshot='sV',
                                                    reservation='v-stby', fence='fV',
                                                    restore_plan='rpV'))['decision'],
                         'promoted')
        self.assertEqual(self.db.execute("SELECT reservation_id FROM bindings WHERE id='bV'").fetchone()[0],
                         'v-stby')

    def test_restore_plan_is_listed_when_candidate_shares_a_domain(self):
        self._overbooked()
        recovery.run(self.db, dict(op='replica', id='oldV', claim='V', rack='rack-a',
                                   generation=1, state='primary'))
        # A fake healthy standby that lands in the same cabinet as the primary.
        recovery.run(self.db, dict(op='replica', id='bad', claim='V', rack='rack-b',
                                   generation=2, state='healthy'))
        recovery.run(self.db, dict(op='snapshot', id='sV', claim='V', generation=1, valid=True))
        recovery.run(self.db, dict(op='plan_restore', id='rp', claim='V', candidate='bad',
                                   snapshot='sV'))
        result = rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        kinds = {(r['kind'], r['object_id']) for r in result['pending']}
        self.assertIn(('restore_plan', 'rp'), kinds)


class EvidenceLifecycleTests(Base):
    def test_late_page_does_not_rewrite_a_commitment(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=10)
        self.two_pools()
        pool.run(self.db, dict(op='reserve', pool='A', id='v', amount=6,
                               rack='rack-a', expires=100))
        pool.run(self.db, dict(op='commit', pool='A', id='v', now=1))
        # A page observed *before* the applied one arrives late.
        result = self.observe(evidence_version='p0', pool='A', rack='rack-a', controller='N1',
                              cabinet='C0', capacity=2, verified=True, observed_at=1)
        self.assertEqual(result['decision'], 'superseded')
        view = rack_evidence.credential_view(self.db)
        self.assertEqual(view['aliases'][('A', 'rack-a')]['evidence_version'], 'p1')
        self.assertEqual(self.db.execute("SELECT state FROM reservations WHERE id='v'").fetchone()[0],
                         'committed')
        # The raw late page is still retained with its original bytes.
        raw = self.db.execute("SELECT * FROM rack_evidence WHERE evidence_version='p0'").fetchone()
        self.assertEqual(raw['state'], 'superseded')
        self.assertEqual(raw['capacity'], 2)

    def test_duplicate_page_is_replayed_not_reapplied(self):
        page = dict(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                    cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.assertEqual(self.observe(**page)['decision'], 'recorded')
        self.assertEqual(self.observe(**page)['decision'], 'replayed')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM rack_evidence").fetchone()[0], 1)

    def test_conflicting_page_is_kept_and_flagged(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        self.volume_v()
        result = self.observe(evidence_version='p2', pool='A', rack='rack-a', controller='N1',
                              cabinet='C9', capacity=8, verified=True, observed_at=2)
        self.assertEqual(result.get('reason'), 'physical_identity_changed')
        # The raw page and its reason survive; reconcile reports the drift.
        raw = self.db.execute("SELECT * FROM rack_evidence WHERE evidence_version='p2'").fetchone()
        self.assertEqual(raw['cabinet'], 'c9')
        rec = rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        self.assertTrue(any(r['reason'] == 'reservation_evidence_changed' for r in rec['pending']))
        # The writer is not detached by the re-pointed page alone.
        self.assertNotEqual(self.db.execute("SELECT state FROM bindings WHERE id='bV'").fetchone()[0],
                            'released')

    def test_frozen_binding_credential_not_swapped_by_new_inventory(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=1)
        self.two_pools()
        self.volume_v()
        frozen = self.db.execute(
            "SELECT physical_key,evidence_version FROM capacity_credentials "
            "WHERE kind='reservation' AND object_id='v'").fetchone()
        self.assertEqual(frozen['physical_key'], 'cabinet:c1')
        self.assertEqual(frozen['evidence_version'], 'p1')
        # A newer page adds a serial; the frozen credential is not rewritten.
        self.observe(evidence_version='p2', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', serial='NEW', capacity=8, verified=True, observed_at=2)
        again = self.db.execute(
            "SELECT physical_key,evidence_version FROM capacity_credentials "
            "WHERE kind='reservation' AND object_id='v'").fetchone()
        self.assertEqual(again['evidence_version'], 'p1')

    def test_unverified_binding_credential_upgrades_in_place(self):
        self.unverified_inventory()
        self.two_pools()
        self.volume_v()
        before = self.db.execute("SELECT physical_key,verified FROM capacity_credentials "
                                 "WHERE kind='reservation' AND object_id='v'").fetchone()
        self.assertEqual(before['verified'], 0)
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=2)
        rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        after = self.db.execute("SELECT physical_key,verified FROM capacity_credentials "
                                "WHERE kind='reservation' AND object_id='v'").fetchone()
        self.assertEqual(after['verified'], 1)
        self.assertEqual(after['physical_key'], 'cabinet:c1')
        self.assertEqual(self.db.execute("SELECT state FROM bindings WHERE id='bV'").fetchone()[0],
                         'bound')


class ReplayTests(Base):
    def test_full_evidence_workflow_replays(self):
        self.unverified_inventory()
        self.two_pools()
        self.volume_v()
        self.standby_for_v()
        self.verified_pages(same_cabinet=True)
        rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        result = replay(self.path, {'pool': pool, 'claim': claim, 'recovery': recovery,
                                    'rack_evidence': rack_evidence})
        self.assertTrue(result['verified'], result['divergences'])
        self.assertGreater(result['decision_count'], 8)

    def test_fail_fixture_blocks_each_malformed_page(self):
        fixture = Path(cloudlab.__file__).resolve().parent.parent / 'fixtures' / 'rack_evidence_fail.json'
        for step in json.loads(fixture.read_text(encoding='utf-8')):
            result = rack_evidence.run(self.db, step)
            self.assertEqual(result['decision'], 'blocked', result)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM rack_evidence").fetchone()[0], 0)

    def test_evidence_is_append_only_across_repairs(self):
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     backplane='BP', capacity=8, observed_at=1)
        self.observe(evidence_version='p2', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=2)
        rows = rack_evidence.run(self.db, dict(op='evidence'))['items']
        self.assertEqual([r['evidence_version'] for r in rows], ['p1', 'p2'])
        # Every page keeps its original observed bytes and identity.
        self.assertEqual(rows[0]['backplane'], 'bp')
        self.assertIsNone(rows[0]['cabinet'])
        self.assertEqual(rows[1]['cabinet'], 'c1')
        self.assertGreaterEqual(len([e for e in report(self.db)
                                     if e['subsystem'] == 'rack_evidence']), 2)

    def test_late_and_repair_pages_still_replay(self):
        self.observe(evidence_version='p2', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=10)
        self.observe(evidence_version='p0', pool='A', rack='rack-a', controller='N1',
                     cabinet='C9', capacity=2, verified=True, observed_at=1)
        self.observe(evidence_version='p1', pool='A', rack='rack-a', controller='N1',
                     cabinet='C1', capacity=8, verified=True, observed_at=5)
        pool.run(self.db, dict(op='define', pool='A', capacity=8, racks=['rack-a', 'spare-a']))
        pool.run(self.db, dict(op='reserve', pool='A', id='r', amount=6,
                               rack='rack-a', expires=100))
        pool.run(self.db, dict(op='commit', pool='A', id='r', now=1))
        rack_evidence.run(self.db, dict(op='reconcile', id='rec'))
        result = replay(self.path, {'pool': pool, 'claim': claim, 'recovery': recovery,
                                    'rack_evidence': rack_evidence})
        self.assertTrue(result['verified'], result['divergences'])


if __name__ == '__main__':
    unittest.main()
