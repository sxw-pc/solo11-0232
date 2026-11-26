"""Cross-site key rotation and per-snapshot readability acceptance.

These tests encode the 卷甲 / S1 / S2 story and every coverage item requested:
parent snapshots on the old key, late offline envelopes, the identical failed
probe split into missing-key / version-mismatch / corruption, external copies
of K, unreachable escrow, revocation failure after read-back, rotation retry
and out-of-order receipts, append-only reports, and the two contract paths.
"""
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect
from cloudlab import (
    key_rotation as kr,
    key_wrap,
    key_service,
    decrypt_probe,
    claim,
    recovery,
)


class KRCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / 'kr.sqlite'))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def call(self, payload):
        return kr.run(self.db, payload)

    # -- canonical 卷甲 story -------------------------------------------
    def story(self, external=False, offline_target=True, holders=None):
        claim.run(self.db, dict(op='declare', id='vol-a', size=100,
                                mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='snapshot', id='S1', claim='vol-a',
                                   generation=1))
        recovery.run(self.db, dict(op='snapshot', id='S2', claim='vol-a',
                                   parent='S1', generation=2))
        key_wrap.record(self.db, 'w1', 'K', 'vol-a', 'S1', 1, 'east', 'active')
        key_wrap.record(self.db, 'w2', 'K', 'vol-a', 'S2', 1, 'west', 'active')
        self.call(dict(op='register_key', id='rkK', key_id='K',
                       claim_id='vol-a', epoch=1, at=1))
        payload = dict(op='rotate', id='rot1', claim_id='vol-a',
                       from_key='K', to_key='K2', at=20,
                       deadline=30, hard_deadline=45)
        if holders is not None:
            payload['holders'] = holders
        if offline_target:
            payload['offline'] = [{'id': 'off-rep-1', 'site': 'west'}]
        if external:
            payload['external'] = [{'id': 'ext-kms',
                                     'location': 'partner-kms',
                                     'holder': 'partner'}]
        rot = self.call(payload)
        self.call(dict(op='receipt', id='rc20', key_id='K2', action='rotate',
                       at=20, site='east', result='done'))
        self.call(dict(op='readback', id='p20', claim_id='vol-a',
                       snapshot_id='S1', key_id='K2', site='east', at=20))
        self.call(dict(op='probe', id='p21', claim_id='vol-a',
                       snapshot_id='S2', key_id='K', site='west', at=21,
                       outcome='failed'))
        return rot


# ---------------------------------------------------------------------------
# 1. the core story: east completion is not global completion
# ---------------------------------------------------------------------------

class CoreStory(KRCase):
    def test_east_receipt_and_s1_do_not_certify_or_permit_revoking_k(self):
        self.story()
        rep = kr.recovery_report(self.db, 'vol-a', at=22)
        self.assertEqual(rep['overall'], 'incomplete')
        self.assertEqual(rep['incomplete_snapshots'], ['S2'])
        self.assertIn('S1', rep['recoverable_snapshots'])
        s2 = next(s for s in rep['snapshots'] if s['snapshot_id'] == 'S2')
        self.assertFalse(s2['allowed'])
        self.assertIn(s2['blocking_reasons'][0],
                      ('no_verified_readback', 'only_failed_probes'))
        self.assertEqual(rep['current_key'], 'K2')
        # the naive "east receipt -> revoke K" flow must be refused
        rv = self.call(dict(op='revoke', id='rv-early', key_id='K', at=22))
        self.assertEqual(rv['decision'], 'blocked')
        self.assertEqual(rv['reason'], 'outstanding_snapshot_readback')
        self.assertEqual(rv['snapshots'], ['S2'])
        # K must not have been silently revoked
        k = self.db.execute("SELECT state FROM kr_keys WHERE key_id='K'").fetchone()
        self.assertEqual(k[0], 'retiring')

    def test_site_boolean_receipt_is_recorded_but_not_readability(self):
        self.story()
        # key service still only knows the east "done" receipt
        row = self.db.execute(
            "SELECT result FROM key_receipts WHERE id='rc20'").fetchone()
        self.assertEqual(row[0], 'done')
        # yet the report is incomplete because S2 has no read-back
        self.assertEqual(kr.recovery_report(self.db, 'vol-a', 22)['overall'],
                         'incomplete')

    def test_failed_probe_alone_is_undetermined_never_corruption(self):
        self.call(dict(op='probe', id='px', claim_id='c', snapshot_id='SX',
                       key_id='K', site='west', at=21, outcome='failed'))
        out = self.call(dict(op='classify', id='ax', probe_id='px'))
        self.assertEqual(out['classification'], 'undetermined')
        self.assertNotEqual(out['classification'], 'ciphertext_corrupt')
        rep = kr.recovery_report(self.db, 'c', at=22)
        sx = next(s for s in rep['snapshots'] if s['snapshot_id'] == 'SX')
        self.assertEqual(sx['classification'], 'undetermined')


# ---------------------------------------------------------------------------
# 2. missing key vs wrap version mismatch vs real corruption
# ---------------------------------------------------------------------------

class FailureClassification(KRCase):
    def _failed(self, sid):
        self.call(dict(op='probe', id='pb-' + sid, claim_id='c',
                       snapshot_id=sid, key_id='K', site='west', at=21,
                       outcome='failed'))

    def test_identical_failed_booleans_split_by_corroborating_evidence(self):
        # case 1: site key store reports K absent (not synced yet)
        self._failed('SMK')
        self.call(dict(op='key_store', id='obs-mk', snapshot_id='SMK',
                       site='west', at=22, key_present=False))
        mk = self.call(dict(op='classify', id='cl-mk', probe_id='pb-SMK'))
        self.assertEqual(mk['classification'], 'missing_key')

        # case 2: key present but envelope version incompatible
        self._failed('SWM')
        self.call(dict(op='wrap_inspection', id='obs-wm', snapshot_id='SWM',
                       site='west', at=22, key_present=True,
                       version_match=False))
        wm = self.call(dict(op='classify', id='cl-wm', probe_id='pb-SWM'))
        self.assertEqual(wm['classification'], 'wrap_version_mismatch')

        # case 3: independent digest/media proof shows ciphertext corruption
        self._failed('SCC')
        self.call(dict(op='ciphertext_check', id='obs-cc', snapshot_id='SCC',
                       site='west', at=22, ciphertext_intact=False,
                       independent=True))
        cc = self.call(dict(op='classify', id='cl-cc', probe_id='pb-SCC'))
        self.assertEqual(cc['classification'], 'ciphertext_corrupt')

        # the three raw probes remain exactly the same boolean failure
        outcomes = [r[0] for r in self.db.execute(
            "SELECT outcome FROM decrypt_probes WHERE id LIKE 'pb-%' ORDER BY id")]
        self.assertEqual(outcomes, ['failed', 'failed', 'failed'])

    def test_authenticated_decryption_failure_is_corruption(self):
        self._failed('SAE')
        out = self.call(dict(op='classify', id='cl-ae', snapshot_id='SAE',
                             unwrap_ok=True, auth_ok=False))
        self.assertEqual(out['classification'], 'ciphertext_corrupt')

    def test_offline_store_not_returned_stays_undetermined(self):
        self._failed('SOF')
        out = self.call(dict(op='classify', id='cl-of', snapshot_id='SOF',
                             store_returned=False))
        self.assertEqual(out['classification'], 'undetermined')


# ---------------------------------------------------------------------------
# 3. parent snapshot still on the old key
# ---------------------------------------------------------------------------

class ParentOldKey(KRCase):
    def test_parent_old_key_only_carries_chain_inside_bounded_window(self):
        claim.run(self.db, dict(op='declare', id='c', size=10,
                                mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='snapshot', id='S1', claim='c',
                                   generation=1))
        recovery.run(self.db, dict(op='snapshot', id='S2', claim='c',
                                   parent='S1', generation=2))
        key_wrap.record(self.db, 'w1', 'K', 'c', 'S1', 1, 'east', 'active')
        key_wrap.record(self.db, 'w2', 'K2', 'c', 'S2', 2, 'west', 'active')
        self.call(dict(op='register_key', id='kK', key_id='K', claim_id='c'))
        self.call(dict(op='rotate', id='r', claim_id='c', from_key='K',
                       to_key='K2', at=20, deadline=30, hard_deadline=40))
        # parent only ever read back under old K
        self.call(dict(op='probe', id='r1', claim_id='c', snapshot_id='S1',
                       key_id='K', site='east', at=20, outcome='success'))
        self.call(dict(op='readback', id='r2', claim_id='c', snapshot_id='S2',
                       key_id='K2', site='west', at=21))

        # inside the coexistence window the bounded legacy grant covers S1
        gate = kr.gate_restore(self.db, 'c', 'S2', at=25)
        self.assertTrue(gate['allowed'], gate['reasons'])
        parent = next(x for x in gate['chain'] if x['snapshot_id'] == 'S1')
        self.assertEqual(parent['readback']['via'], 'legacy_window')

        # after the deadline the old-key parent blocks the whole child restore
        gate = kr.gate_restore(self.db, 'c', 'S2', at=31)
        self.assertFalse(gate['allowed'])
        self.assertIn('readback_key_not_current', gate['reasons'])

        # fresh K2 read-back of the parent closes the gap
        self.call(dict(op='readback', id='r1k2', claim_id='c', snapshot_id='S1',
                       key_id='K2', site='east', at=32))
        gate = kr.gate_restore(self.db, 'c', 'S2', at=32)
        self.assertTrue(gate['allowed'], gate['reasons'])


# ---------------------------------------------------------------------------
# 4. path A: quarantine, late independent wrap, re-encrypt, read back
# ---------------------------------------------------------------------------

class PathAQuarantine(KRCase):
    def test_quarantine_excludes_s2_then_evidence_restores_it(self):
        self.story()
        q = self.call(dict(op='quarantine', id='q1', snapshot_id='S2', at=22,
                           reason='unresolved_west_failure'))
        self.assertEqual(q['decision'], 'quarantined')
        self.assertEqual(q['quarantined'], ['S2'])

        rep = self.call(dict(op='report', id='rpt1', claim_id='vol-a', at=22))
        self.assertEqual(rep['decision'], 'issued')
        self.assertEqual(rep['overall'], 'quarantined')
        self.assertEqual(rep['quarantined'], ['S2'])
        self.assertIn('S1', rep['recoverable_snapshots'])

        # while quarantined the restore gate is explicit
        gate = kr.gate_restore(self.db, 'vol-a', 'S2', at=23)
        self.assertFalse(gate['allowed'])
        self.assertIn('snapshot_quarantined', gate['reasons'])

        # quarantine moves S2 out of the promised set, so K may be revoked
        rv = self.call(dict(op='revoke', id='rv1', key_id='K', at=24))
        self.assertEqual(rv['decision'], 'revoked', rv)

        # late west offline store returns an independent K envelope for S2
        imp = self.call(dict(
            op='offline_wraps', id='batch23', claim_id='vol-a', site='west',
            at=23, wraps=[dict(id='w3', key_id='K', snapshot_id='S2',
                               epoch=1, site='west', status='offline_reported')]))
        self.assertEqual(imp['decision'], 'imported')
        self.assertEqual(imp['recorded'], 1)

        # ciphertext media read-back / digest is intact
        co = self.call(dict(op='ciphertext_check', id='co1', snapshot_id='S2',
                            site='west', at=24, ciphertext_intact=True,
                            independent=True))
        self.assertEqual(co['decision'], 'observed')

        # re-encryption to K2 is authorized by quarantine + independent wrap
        rw = self.call(dict(op='rewrap', id='w2k2', wrap_id='w2k2',
                            snapshot_id='S2', from_key='K', to_key='K2',
                            site='west', at=25, source_wrap='w3'))
        self.assertEqual(rw['decision'], 'rewrapped', rw.get('reason'))

        # K2 customer read-back verifies but does not auto-lift quarantine
        rb = self.call(dict(op='readback', id='p26', snapshot_id='S2',
                            key_id='K2', site='west', at=26))
        self.assertEqual(rb['decision'], 'readback_verified')
        self.assertTrue(rb['release_required'])
        self.assertFalse(kr.gate_restore(self.db, 'vol-a', 'S2', at=26)['allowed'])

        rel = self.call(dict(op='release', id='rel1', snapshot_id='S2', at=27))
        self.assertEqual(rel['decision'], 'released', rel.get('reason'))
        self.assertTrue(kr.gate_restore(self.db, 'vol-a', 'S2', at=27)['allowed'])

        rep2 = self.call(dict(op='report', id='rpt2', claim_id='vol-a', at=27))
        self.assertEqual(rep2['overall'], 'certified')
        self.assertEqual(rep2['quarantined'], [])

        # revoked K is no longer usable
        denied = self.call(dict(op='access', id='acK', key_id='K',
                                holder='east', purpose='unwrap',
                                ref_id='S1', at=28))
        self.assertEqual(denied['decision'], 'denied')
        self.assertEqual(denied['reason'], 'key_revoked')

    def test_rewrap_without_independent_wrap_or_ciphertext_proof_blocked(self):
        self.story()
        self.call(dict(op='quarantine', id='q1', snapshot_id='S2', at=22))
        rw = self.call(dict(op='rewrap', id='rw1', snapshot_id='S2',
                            to_key='K2', site='west', at=23))
        self.assertEqual(rw['decision'], 'blocked')
        self.assertIn(rw['reason'],
                      ('independent_wrap_required',
                       'ciphertext_readback_required'))


# ---------------------------------------------------------------------------
# 5. late offline envelopes are append-only scope discoveries
# ---------------------------------------------------------------------------

class LateOfflineWraps(KRCase):
    def test_late_wraps_append_and_never_rewrite_minute21_failure(self):
        self.story()
        before = self.db.execute('SELECT COUNT(*) FROM key_wraps').fetchone()[0]
        imp = self.call(dict(
            op='offline_wraps', id='batch23', claim_id='vol-a', site='west',
            at=23, wraps=[
                dict(id='w3', key_id='K', snapshot_id='S2', epoch=1,
                     site='west'),
                dict(id='w4', key_id='K', snapshot_id='S3-old', epoch=1,
                     site='west'),
            ]))
        self.assertEqual(imp['decision'], 'imported')
        after = self.db.execute('SELECT COUNT(*) FROM key_wraps').fetchone()[0]
        self.assertEqual(after, before + 2)
        # batch retry is idempotent at the batch marker, wrap ids are seed-idempotent
        again = self.call(dict(
            op='offline_wraps', id='batch23', claim_id='vol-a', site='west',
            at=23, wraps=[]))
        self.assertEqual(again['decision'], 'reused')

        # the newly reported S3-old envelope expands scope and is unverified
        rep = kr.recovery_report(self.db, 'vol-a', at=24)
        ids = {s['snapshot_id'] for s in rep['snapshots']}
        self.assertIn('S3-old', ids)
        self.assertIn('S3-old', rep['incomplete_snapshots'])

        # the customer's minute-21 failure is still present and failed
        row = self.db.execute(
            "SELECT outcome,at FROM decrypt_probes WHERE id='p21'").fetchone()
        self.assertEqual(tuple(row), ('failed', 21))
        hist = kr.incident_history(self.db, claim_id='vol-a',
                                  snapshot_id='S2')
        failures = [h for h in hist if h['kind'] == 'decrypt_probe'
                    and h.get('outcome') == 'failed']
        self.assertTrue(any(h['at'] == 21 for h in failures))


# ---------------------------------------------------------------------------
# 6. old key coexistence: purpose / holders / deadline / compromise
# ---------------------------------------------------------------------------

class LegacyKeyBounds(KRCase):
    def _rotation(self, deadline=30, hard=45, holders=None):
        self.call(dict(op='register_key', id='kK', key_id='K', claim_id='c'))
        p = dict(op='rotate', id='r', claim_id='c', from_key='K',
                  to_key='K2', at=20, deadline=deadline,
                  hard_deadline=hard)
        if holders is not None:
            p['holders'] = holders
        self.call(p)

    def test_renewal_is_capped_and_compromise_kills_renewal(self):
        self._rotation()
        ok = self.call(dict(op='renew', id='rn1', key_id='K',
                            new_deadline=35, at=24))
        self.assertEqual(ok['decision'], 'renewed')
        self.assertEqual(ok['deadline'], 35)
        capped = self.call(dict(op='renew', id='rn2', key_id='K',
                                new_deadline=99, at=25,
                                reason='read_service'))
        self.assertEqual(capped['decision'], 'denied')
        self.assertEqual(capped['reason'], 'renewal_beyond_hard_deadline')

        self.call(dict(op='compromise', id='cmp', key_id='K', at=26,
                       proof='leak-report-7'))
        denied = self.call(dict(op='renew', id='rn3', key_id='K',
                                new_deadline=36, at=27,
                                reason='read_service_needs'))
        self.assertEqual(denied['decision'], 'denied')
        self.assertEqual(denied['reason'],
                         'compromised_key_renewal_denied')

    def test_holder_purpose_scope_and_deadline_are_enforced(self):
        self._rotation(holders=['east-svc', 'west-escrow'])
        ok = self.call(dict(op='access', id='a1', key_id='K',
                            holder='east-svc', purpose='unwrap',
                            ref_id='S1', at=24))
        self.assertEqual(ok['decision'], 'allowed')
        stranger = self.call(dict(op='access', id='a2', key_id='K',
                                  holder='mallory', purpose='unwrap',
                                  ref_id='S1', at=24))
        self.assertEqual(stranger['reason'], 'holder_not_authorized')
        bad_purpose = self.call(dict(op='access', id='a3', key_id='K',
                                     holder='east-svc', purpose='sign',
                                     ref_id='S1', at=24))
        self.assertEqual(bad_purpose['reason'], 'purpose_not_permitted')
        expired = self.call(dict(op='access', id='a4', key_id='K',
                                 holder='east-svc', purpose='unwrap',
                                 ref_id='S1', at=31))
        self.assertEqual(expired['decision'], 'denied')
        self.assertEqual(expired['reason'], 'legacy_window_expired')


# ---------------------------------------------------------------------------
# 7. path B: verified closed escrow, narrow case, separate proofs
# ---------------------------------------------------------------------------

class PathBEscrow(KRCase):
    def _ready_case(self):
        self.story()
        reg = self.call(dict(op='register_escrow', id='env', site='west',
                             holder='west-custodian', verified=True,
                             proof='soc2-closed-env'))
        self.assertEqual(reg['decision'], 'registered')
        ct = self.call(dict(op='escrow_contact', id='ct1', env_id='env',
                            at=22, reachable=True, proof='contact-ping'))
        self.assertEqual(ct['decision'], 'contact_recorded')
        case = self.call(dict(op='open_escrow', id='case1', env_id='env',
                               key_id='K', snapshot_id='S2', at=23,
                               deadline=30))
        self.assertEqual(case['decision'], 'escrow_opened')
        return case

    def test_escrow_keeps_s2_recoverable_then_rewrap_and_separate_destroy(self):
        self._ready_case()
        # no access proof yet -> neither access nor rewrap may proceed
        no_proof = self.call(dict(op='escrow_access', id='ea0',
                                  case_id='case1', holder='west-custodian',
                                  at=24))
        self.assertEqual(no_proof['decision'], 'blocked')
        self.assertEqual(no_proof['reason'], 'access_proof_required')
        rw0 = self.call(dict(op='rewrap', id='rw0', snapshot_id='S2',
                             to_key='K2', at=24, window_id='case1'))
        self.assertEqual(rw0['reason'], 'escrow_access_proof_required')

        acc = self.call(dict(op='escrow_access', id='ea1', case_id='case1',
                             holder='west-custodian', at=24,
                             proof='split-custody-proof'))
        self.assertEqual(acc['decision'], 'escrow_access_recorded')

        # custodian unwraps K only for S2 and the read succeeds in-window
        self.call(dict(op='probe', id='p24', claim_id='vol-a',
                       snapshot_id='S2', key_id='K', site='west', at=24,
                       outcome='success'))
        rep = kr.recovery_report(self.db, 'vol-a', at=24)
        self.assertEqual(rep['overall'], 'restricted')
        s2 = next(s for s in rep['snapshots'] if s['snapshot_id'] == 'S2')
        self.assertEqual(s2['acceptance'], 'escrow_only')
        self.assertEqual(s2['readback']['via'], 'escrow_window')
        self.assertTrue(kr.gate_restore(self.db, 'vol-a', 'S2', at=25)['allowed'])

        # immediate re-wrap to K2 + customer read-back completes the path
        rw = self.call(dict(op='rewrap', id='w2k2', snapshot_id='S2',
                            to_key='K2', site='west', at=25,
                            window_id='case1'))
        self.assertEqual(rw['decision'], 'rewrapped', rw.get('reason'))
        rb = self.call(dict(op='readback', id='p26', snapshot_id='S2',
                            key_id='K2', site='west', at=26))
        self.assertTrue(rb['accepted'])
        rep = kr.recovery_report(self.db, 'vol-a', at=26)
        self.assertEqual(rep['overall'], 'certified')

        # contact/access proof alone cannot prove destruction
        d0 = self.call(dict(op='destroy', id='d0', key_id='K', at=27))
        self.assertEqual(d0['decision'], 'blocked')
        self.assertEqual(d0['reason'], 'destruction_proof_required')
        # revocation then a separate destruction certificate
        rv = self.call(dict(op='revoke', id='rv1', key_id='K', at=27))
        self.assertEqual(rv['decision'], 'revoked')
        d1 = self.call(dict(op='destroy', id='d1', key_id='K', at=28,
                            proof='destroy-witness-hsm-9'))
        self.assertEqual(d1['decision'], 'destroyed')
        k = self.db.execute(
            "SELECT state,destruction_proof FROM kr_keys WHERE key_id='K'").fetchone()
        self.assertEqual(k[0], 'destroyed')
        self.assertEqual(k[1], 'destroy-witness-hsm-9')
        w = self.db.execute(
            "SELECT access_proof FROM kr_windows WHERE id='case1'").fetchone()
        self.assertEqual(w[0], 'split-custody-proof')
        self.assertNotEqual(w[0], k[1])

    def test_escrow_window_is_scoped_to_the_single_snapshot(self):
        self._ready_case()
        self.call(dict(op='escrow_access', id='ea1', case_id='case1',
                       holder='west-custodian', at=24, proof='ap'))
        denied = self.call(dict(op='access', id='ax', window_id='case1',
                                key_id='K', holder='west-custodian',
                                purpose='unwrap', ref_id='S1', at=24))
        self.assertEqual(denied['reason'], 'snapshot_scope_denied')

    def test_unreachable_holder_blocks_escrow_and_falls_back_to_quarantine(self):
        self.story()
        self.call(dict(op='register_escrow', id='env', site='west',
                       holder='custodian', verified=True, proof='vp'))
        self.call(dict(op='escrow_contact', id='ct', env_id='env', at=22,
                       reachable=False))
        opened = self.call(dict(op='open_escrow', id='caseX', env_id='env',
                                key_id='K', snapshot_id='S2', at=23,
                                deadline=28))
        self.assertEqual(opened['decision'], 'blocked')
        self.assertEqual(opened['reason'], 'escrow_holder_unreachable')
        # inline unreachable signal is refused as well
        opened2 = self.call(dict(op='open_escrow', id='caseY', env_id='env',
                                 key_id='K', snapshot_id='S2', at=23,
                                 reachable=False))
        self.assertEqual(opened2['reason'], 'escrow_holder_unreachable')
        # platform falls back to path A
        q = self.call(dict(op='quarantine', id='q1', snapshot_id='S2', at=23))
        self.assertEqual(q['decision'], 'quarantined')
        self.assertEqual(
            kr.recovery_report(self.db, 'vol-a', 23)['overall'], 'quarantined')

    def test_unverified_escrow_environment_cannot_open_case(self):
        reg = self.call(dict(op='register_escrow', id='env0', site='west',
                             holder='h', verified=True))
        self.assertEqual(reg['decision'], 'blocked')
        self.assertEqual(reg['reason'],
                         'environment_verification_proof_required')


# ---------------------------------------------------------------------------
# 8. external copy of K
# ---------------------------------------------------------------------------

class ExternalCopy(KRCase):
    def test_external_copy_blocks_revocation_until_attested(self):
        self.story(external=True)
        # take S2 out of the way first so the external copy is the sole blocker
        self.call(dict(op='quarantine', id='q1', snapshot_id='S2', at=22))
        rv = self.call(dict(op='revoke', id='rv1', key_id='K', at=24))
        self.assertEqual(rv['decision'], 'blocked')
        self.assertEqual(rv['reason'], 'external_copy_unsecured')
        self.assertEqual(rv['external_copies'], ['ext-kms'])

        no_proof = self.call(dict(op='attest_external_copy', id='ext-kms',
                                  disposition='destroyed'))
        self.assertEqual(no_proof['decision'], 'blocked')
        self.assertEqual(no_proof['reason'], 'attestation_proof_required')

        att = self.call(dict(op='attest_external_copy', id='ext-kms',
                             disposition='destroyed', proof='partner-destroy-2'))
        self.assertEqual(att['decision'], 'attested')
        rv2 = self.call(dict(op='revoke', id='rv2', key_id='K', at=25))
        self.assertEqual(rv2['decision'], 'revoked', rv2.get('reason'))


# ---------------------------------------------------------------------------
# 9. revocation failure after read-back is surfaced and retryable
# ---------------------------------------------------------------------------

class RevocationFailure(KRCase):
    def test_failed_revocation_is_visible_then_succeeds_on_retry(self):
        self.story()
        # finish S2 on K2 directly
        key_wrap.record(self.db, 'w2k2', 'K2', 'vol-a', 'S2', 2, 'west', 'active')
        self.call(dict(op='readback', id='p22', snapshot_id='S2', key_id='K2',
                       site='west', at=22))
        self.assertEqual(
            kr.recovery_report(self.db, 'vol-a', 22)['overall'], 'certified')

        bad = self.call(dict(op='revoke', receipt_id='rvf', key_id='K',
                             at=23, result='failed'))
        self.assertEqual(bad['decision'], 'revocation_failed')
        rep = kr.recovery_report(self.db, 'vol-a', at=23)
        self.assertEqual(rep['overall'], 'revocation_failed')
        self.assertEqual(len(rep['revocation_failures']), 1)
        k = self.db.execute(
            "SELECT state,revoke_status FROM kr_keys WHERE key_id='K'").fetchone()
        self.assertEqual(k[0], 'retiring')
        self.assertEqual(k[1], 'failed')
        # raw key-service failed receipt exists too
        raw = self.db.execute(
            "SELECT result FROM key_receipts WHERE id='rvf'").fetchone()
        self.assertEqual(raw[0], 'failed')

        ok = self.call(dict(op='revoke', receipt_id='rvok', key_id='K', at=24))
        self.assertEqual(ok['decision'], 'revoked')
        rep = kr.recovery_report(self.db, 'vol-a', at=24)
        self.assertEqual(rep['overall'], 'certified')
        # the failed attempt stays as append-only history, but is no longer open
        self.assertEqual(len(rep['revocation_failure_history']), 1)
        self.assertEqual(rep['open_revocation_failures'], [])


# ---------------------------------------------------------------------------
# 10. rotation retry, competing rotations, out-of-order receipts
# ---------------------------------------------------------------------------

class RotationFencing(KRCase):
    def test_duplicate_retry_is_reused_and_competitor_is_stale(self):
        self.call(dict(op='register_key', id='kK', key_id='K', claim_id='c'))
        payload = dict(op='rotate', id='rot1', claim_id='c', from_key='K',
                       to_key='K2', at=20)
        self.assertEqual(self.call(payload)['decision'], 'rotation_started')
        self.assertEqual(self.call(payload)['decision'], 'reused')
        competitor = self.call(dict(op='rotate', id='rot2', claim_id='c',
                                    from_key='K', to_key='K3', at=21))
        self.assertEqual(competitor['decision'], 'blocked')
        self.assertEqual(competitor['reason'], 'stale_key_epoch')
        currents = self.db.execute(
            "SELECT key_id FROM kr_keys WHERE claim_id='c' AND state='current'"
        ).fetchall()
        self.assertEqual([r[0] for r in currents], ['K2'])

    def test_out_of_order_receipts_are_flagged_but_never_rewrite_current(self):
        self.call(dict(op='register_key', id='kK', key_id='K', claim_id='c'))
        self.call(dict(op='rotate', id='rot1', claim_id='c', from_key='K',
                       to_key='K2', at=20))
        first = self.call(dict(op='receipt', id='rr20', key_id='K2',
                               action='rotate', at=20, site='east',
                               result='done'))
        late = self.call(dict(op='receipt', id='rr19', key_id='K2',
                              action='rotate', at=19, site='east',
                              result='done'))
        self.assertFalse(first['stale'])
        self.assertTrue(late['stale'])
        self.assertEqual(kr._current_key_id(self.db, 'c'), 'K2')
        n = self.db.execute(
            "SELECT COUNT(*) FROM kr_keys WHERE claim_id='c' AND state='current'"
        ).fetchone()[0]
        self.assertEqual(n, 1)

    def test_idempotent_named_wrapper(self):
        self.assertEqual(
            kr.register_key(self.db, key_id='K', claim_id='c')['decision'],
            'registered')
        self.assertEqual(
            kr.start_rotation(self.db, rotation_id='r', claim_id='c',
                              from_key='K', to_key='K2', at=20)['decision'],
            'rotation_started')
        again = kr.start_rotation(self.db, rotation_id='r', claim_id='c',
                                  from_key='K', to_key='K2', at=20)
        self.assertEqual(again['decision'], 'reused')


# ---------------------------------------------------------------------------
# 11. reports are immutable versions; failures cannot be rewritten
# ---------------------------------------------------------------------------

class AppendOnlyReports(KRCase):
    def test_issued_reports_keep_quarantine_and_probe_conflict_persists(self):
        self.story()
        self.call(dict(op='quarantine', id='q1', snapshot_id='S2', at=22))
        r1 = self.call(dict(op='report', id='rpt1', claim_id='vol-a', at=22))
        self.assertEqual(r1['version'], 1)

        # more evidence arrives and S2 is restored
        key_wrap.record(self.db, 'w2k2', 'K2', 'vol-a', 'S2', 2, 'west', 'active')
        self.call(dict(op='readback', id='p26', snapshot_id='S2', key_id='K2',
                       site='west', at=26))
        self.call(dict(op='release', id='rel1', snapshot_id='S2', at=27))
        r2 = self.call(dict(op='report', id='rpt2', claim_id='vol-a', at=27))
        self.assertEqual(r2['version'], 2)
        self.assertEqual(r2['overall'], 'certified')

        history = kr.report_history(self.db, 'vol-a')
        self.assertEqual([h['version'] for h in history], [1, 2])
        old = kr.get_report(self.db, 'rpt1')
        self.assertEqual(old['overall'], 'quarantined')
        self.assertEqual(old['quarantined'], ['S2'])

        # re-issuing the same report id never creates a new version
        reused = self.call(dict(op='report', id='rpt1', claim_id='vol-a'))
        self.assertEqual(reused['decision'], 'reused')
        self.assertEqual(len(kr.report_history(self.db, 'vol-a')), 2)

        # the customer's p21 failure cannot be overwritten with success
        rewrite = decrypt_probe.result(self.db, 'p21', 'vol-a', 'S2', 'K2',
                                       'west', 26, 'success')
        self.assertEqual(rewrite['decision'], 'conflict')
        row = self.db.execute(
            "SELECT key_id,outcome,at FROM decrypt_probes WHERE id='p21'").fetchone()
        self.assertEqual(tuple(row), ('K', 'failed', 21))
        # and through the acceptance wrapper the same immutability holds
        wrapped = self.call(dict(op='readback', id='p21', snapshot_id='S2',
                                 key_id='K2', site='west', at=26))
        self.assertEqual(wrapped['decision'], 'conflict')


# ---------------------------------------------------------------------------
# 12. integration with recovery chain and restore plans
# ---------------------------------------------------------------------------

class RecoveryIntegration(KRCase):
    def test_existing_recovery_says_restorable_but_key_gate_does_not(self):
        claim.run(self.db, dict(op='declare', id='c', size=20,
                                mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='replica', id='new', claim='c',
                                   rack='b', generation=2, state='healthy'))
        recovery.run(self.db, dict(op='snapshot', id='S1', claim='c',
                                   generation=1))
        recovery.run(self.db, dict(op='snapshot', id='S2', claim='c',
                                   parent='S1', generation=2))
        pr = recovery.run(self.db, dict(op='plan_restore', id='rp', claim='c',
                                        candidate='new', snapshot='S2'))
        self.assertEqual(pr['decision'], 'restorable')

        # parent chain is valid, but no decryption path exists yet
        gate = kr.gate_restore(self.db, 'c', 'S2')
        self.assertFalse(gate['allowed'])
        self.assertIn('no_verified_readback', gate['reasons'])

        rep = kr.recovery_report(self.db, 'c')
        plan = rep['restore_plans'][0]
        self.assertEqual(plan['id'], 'rp')
        self.assertFalse(plan['read_gate']['allowed'])

        certified = self.call(dict(op='certified_restore_plan', id='crp1',
                                   claim_id='c', candidate='new',
                                   snapshot_id='S2'))
        self.assertEqual(certified['decision'], 'blocked')

        # real read-backs for both chain members
        key_wrap.record(self.db, 'w1', 'K2', 'c', 'S1', 2, 'east', 'active')
        key_wrap.record(self.db, 'w2', 'K2', 'c', 'S2', 2, 'west', 'active')
        self.call(dict(op='register_key', id='k2', key_id='K2', claim_id='c',
                       epoch=2))
        self.call(dict(op='readback', id='p1', snapshot_id='S1', key_id='K2',
                       site='east', at=30))
        self.call(dict(op='readback', id='p2', snapshot_id='S2', key_id='K2',
                       site='west', at=31))
        self.assertTrue(kr.gate_restore(self.db, 'c', 'S2', at=31)['allowed'])
        done = self.call(dict(op='certified_restore_plan', id='crp1',
                              claim_id='c', candidate='new',
                              snapshot_id='S2', at=31))
        self.assertEqual(done['decision'], 'certified')
        again = self.call(dict(op='certified_restore_plan', id='crp1',
                               claim_id='c', candidate='new',
                               snapshot_id='S2', at=31))
        self.assertEqual(again['decision'], 'reused')
        rep = kr.recovery_report(self.db, 'c', at=31)
        self.assertTrue(rep['restore_plans'][0]['read_gate']['allowed'])

    def test_opt_in_recovery_plan_enforces_readability(self):
        claim.run(self.db, dict(op='declare', id='c', size=20,
                                mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='replica', id='new', claim='c',
                                   rack='b', generation=2, state='healthy'))
        recovery.run(self.db, dict(op='snapshot', id='S1', claim='c',
                                   generation=1))
        # default legacy behavior still plans fine without key evidence
        legacy = recovery.run(self.db, dict(op='plan_restore', id='rp0',
                                            claim='c', candidate='new',
                                            snapshot='S1'))
        self.assertEqual(legacy['decision'], 'restorable')
        # opt-in readability flag blocks the same plan on a new plan id
        blocked = recovery.run(self.db, dict(op='plan_restore', id='rp1',
                                             claim='c', candidate='new',
                                             snapshot='S1',
                                             require_readback=True))
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'snapshot_not_readable')


# ---------------------------------------------------------------------------
# 13. rotation scope reaches online volume, parents, offline, external
# ---------------------------------------------------------------------------

class RotationScope(KRCase):
    def test_scope_enumerates_every_surface_and_reports_wrap_gaps(self):
        claim.run(self.db, dict(op='declare', id='c', size=10,
                                mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='snapshot', id='S1', claim='c',
                                   generation=1))
        recovery.run(self.db, dict(op='snapshot', id='S2', claim='c',
                                   parent='S1', generation=2))
        key_wrap.record(self.db, 'w1', 'K', 'c', 'S1', 1, 'east', 'active')
        key_wrap.record(self.db, 'w2', 'K', 'c', 'S2', 1, 'west', 'active')
        self.call(dict(op='register_key', id='kK', key_id='K', claim_id='c'))
        rot = self.call(dict(
            op='rotate', id='rot', claim_id='c', from_key='K', to_key='K2',
            at=20,
            offline=[{'id': 'off-1', 'site': 'cold-vault'}],
            external=[{'id': 'ext-1', 'location': 'other-cloud-kms'}]))
        kinds = set(rot['scope']['kinds'])
        self.assertIn('online_volume', kinds)
        self.assertIn('snapshot', kinds)
        self.assertIn('offline_replica', kinds)
        self.assertIn('external_wrap', kinds)
        refs = {t['ref_id'] for t in rot['scope']['targets']
                if t['kind'] == 'snapshot'}
        self.assertEqual(refs, {'S1', 'S2'})
        self.assertEqual(rot['scope']['gaps'], [])

        # a new parent-chain snapshot without any envelope is a scope gap
        recovery.run(self.db, dict(op='snapshot', id='S3', claim='c',
                                   parent='S2', generation=3))
        scope = kr.rotation_scope(self.db, rotation_id='rot')
        self.assertTrue(any(g['snapshot_id'] == 'S3'
                            and g['kind'] == 'missing_wrap'
                            for g in scope['gaps']))


# ---------------------------------------------------------------------------
# 14. API surface hedges (dict/kwargs/positional/facade/dynamic names)
# ---------------------------------------------------------------------------

class APISurface(KRCase):
    def test_named_functions_accept_dict_and_kwargs(self):
        out = kr.register_key(self.db, {'key_id': 'K', 'claim_id': 'c'})
        self.assertEqual(out['decision'], 'registered')
        rep = kr.readiness_report(self.db, 'c')
        self.assertIn(rep['overall'], ('incomplete', 'certified'))

    def test_dynamic_alias_and_service_facade(self):
        self.call(dict(op='probe', id='p', claim_id='c', snapshot_id='S',
                       key_id='K', site='w', at=1, outcome='failed'))
        out = kr.diagnose_snapshot_failure(
            self.db, {'probe_id': 'p', 'key_present': False})
        self.assertEqual(out['classification'], 'missing_key')

        svc = kr.KeyRotationService(self.db)
        q = svc.quarantine_snapshot({'snapshot_id': 'S', 'at': 2})
        self.assertEqual(q['decision'], 'quarantined')
        gate = svc.can_restore(claim_id='c', snapshot_id='S')
        self.assertFalse(gate['allowed'])

    def test_constants_export_canonical_classifications(self):
        self.assertEqual(kr.MISSING_KEY, 'missing_key')
        self.assertEqual(kr.WRAP_VERSION_MISMATCH, 'wrap_version_mismatch')
        self.assertEqual(kr.CIPHERTEXT_CORRUPT, 'ciphertext_corrupt')

    def test_snapshot_first_positional_wrappers(self):
        kr.quarantine_snapshot(self.db, 'SX', 5, 'suspect')
        row = self.db.execute(
            "SELECT state,reason,since FROM kr_acceptance WHERE snapshot_id='SX'"
        ).fetchone()
        self.assertEqual(tuple(row), ('quarantined', 'suspect', 5))
        # id-first seed style also works
        kr.quarantine_snapshot(self.db, 'q2', 'SY', 6)
        ev = self.db.execute(
            "SELECT snapshot_id FROM kr_events WHERE id='q2'").fetchone()
        self.assertEqual(ev[0], 'SY')

    def test_revoke_key_key_first_positional_and_readiness(self):
        self.story()
        ready = kr.revocation_readiness(self.db, 'K', at=22)
        self.assertFalse(ready['may_revoke'])
        self.assertEqual(ready['reasons'],
                         ['outstanding_snapshot_readback'])
        kr.run(self.db, dict(op='quarantine', id='q', snapshot_id='S2', at=22))
        ready = kr.may_revoke(self.db, 'K', 23)
        self.assertTrue(ready['may_revoke'])
        out = kr.revoke_key(self.db, 'K', 24)  # key-first positional
        self.assertEqual(out['decision'], 'revoked')

    def test_dynamic_alias_maps_positional_args(self):
        self.call(dict(op='probe', id='pz', claim_id='c', snapshot_id='Z',
                       key_id='K', site='w', at=1, outcome='failed'))
        out = kr.classify_snapshot_failure(self.db, 'pz')
        self.assertIn(out['classification'], kr.CLASSIFICATIONS)
        self.assertEqual(out['classification'], 'undetermined')


if __name__ == '__main__':
    unittest.main()
