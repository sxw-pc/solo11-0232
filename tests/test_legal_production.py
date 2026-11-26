"""Tests for the court legal production workflow.

The acceptance evidence: volume V at point in time 20 has snapshot S2 whose
ancestor is S1.  Page 7 of S2 carries both in-scope bytes A (56..59) and
third-party bytes B (60..63).  S1 is later invalidated, but an independent
controller holds signed pages for the same point in time with a continuous
hash chain proving the exact A content.
"""
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, replay
from cloudlab import pool, claim, recovery
from cloudlab import legal_production as lp

PAGE7 = bytes([10, 11, 12, 13, 99, 98, 97, 96])
A_BYTES = PAGE7[:4]
B_BYTES = PAGE7[4:]
COURT_SECRET = 'cc' * 32
AGENT_SECRET = 'dd' * 32
CONTROLLER_MATERIAL = 'aa' * 32
COURT_RECIPIENTS = [
    {'id': 'court', 'role': 'court', 'clearance': 'secret'},
    {'id': 'agent', 'role': 'agent', 'clearance': 'confidential'},
]


class LegalProductionBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / 'state.sqlite'))
        self.build_evidence()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def build_evidence(self, invalidate_s1=False, later_s3=False):
        claim.run(self.db, dict(op='declare', id='V', size=64, mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='snapshot', id='S1', claim='V', generation=1))
        recovery.run(self.db, dict(op='snapshot', id='S2', claim='V', parent='S1', generation=2))
        lp.run(self.db, dict(op='register_controller_key', id='independent-controller',
                             material_hex=CONTROLLER_MATERIAL))
        lp.run(self.db, dict(op='register_page_evidence', id='ev7', snapshot='S2', claim='V',
                             page_no=7, data_hex=PAGE7.hex(), confirmed_at=20,
                             segments=[[0, 4, 'scopeA'], [4, 8, 'scopeB']]))
        anchor = lp.attestation_anchor('independent-controller', 'V')
        page_hash = hashlib.sha256(PAGE7).hexdigest()
        signature = lp._sign(CONTROLLER_MATERIAL,
                             '|'.join(('independent-controller', 'V', '20', '7', page_hash, anchor)))
        chain_hash = hashlib.sha256((anchor + ':' + page_hash).encode('utf-8')).hexdigest()
        lp.run(self.db, dict(op='register_attestation', id='att7', controller='independent-controller',
                             claim='V', point_in_time=20, page_no=7, snapshot='S2',
                             data_hash=page_hash, prev_hash=anchor, signature=signature,
                             chain_hash=chain_hash))
        lp.run(self.db, dict(op='register_recipient_key', id='court-key', recipient='court',
                             secret_hex=COURT_SECRET, clearance='secret'))
        lp.run(self.db, dict(op='register_recipient_key', id='agent-key', recipient='agent',
                             secret_hex=AGENT_SECRET, clearance='confidential'))
        if invalidate_s1:
            recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        if later_s3:
            recovery.run(self.db, dict(op='snapshot', id='S3', claim='V', parent='S2', generation=3))
            lp.run(self.db, dict(op='register_page_evidence', id='ev7-s3', snapshot='S3', claim='V',
                                 page_no=7, data_hex=bytes([0] * 8).hex(), confirmed_at=40,
                                 segments=[[0, 8, 'scopeA']]))

    def freeze(self, warrant='w1', request_key='req-1', point_in_time=20, byte_range=(56, 60),
               classification='confidential', expires_at=100, now=25, recipients=None,
               scope_id='scopeA'):
        return lp.run(self.db, dict(op='freeze_warrant', id=warrant, request_key=request_key,
                                    claim='V', point_in_time=point_in_time,
                                    byte_range=list(byte_range), scope_id=scope_id,
                                    classification=classification, expires_at=expires_at, now=now,
                                    recipients=COURT_RECIPIENTS if recipients is None else recipients))

    def prepare(self, delivery, route, warrant='w1', now=26, **extra):
        payload = dict(op='prepare_delivery', id=delivery, warrant=warrant, route=route, now=now)
        payload.update(extra)
        return lp.run(self.db, payload)

    def open_artifact(self, delivery, recipient, kind):
        row = self.db.execute(
            'SELECT * FROM legal_artifacts WHERE delivery_id=? AND recipient_id=? AND kind=?',
            (delivery, recipient, kind)).fetchone()
        key = self.db.execute('SELECT * FROM legal_recipient_keys WHERE key_id=?',
                              (row['key_id'],)).fetchone()
        context = '%s:%d' % (row['artifact_id'], key['version'])
        return lp.open_artifact(key['secret_hex'], context, bytes(row['content']))

    def all_blob_bytes(self):
        return b'\n'.join(bytes(r['content']) for r in
                          self.db.execute('SELECT content FROM legal_artifacts').fetchall())

    def receipt_all(self, delivery, now=29):
        artifacts = self.db.execute('SELECT * FROM legal_artifacts WHERE delivery_id=?',
                                    (delivery,)).fetchall()
        for index, artifact in enumerate(artifacts):
            lp.run(self.db, dict(op='ack_receipt', id='rc-%s-%d' % (delivery, index),
                                 delivery=delivery, recipient=artifact['recipient_id'],
                                 artifact=artifact['artifact_id'], now=now))


class WarrantFreezeTest(LegalProductionBase):
    def test_warrant_freezes_all_court_terms_and_binding_identity(self):
        # Build a real bound volume so the frozen binding token is captured.
        pool.run(self.db, dict(op='define', pool='p', capacity=200, racks=['a', 'b']))
        pool.run(self.db, dict(op='place', pool='p', id='plan', replica_size=70, racks=['a', 'b']))
        pool.run(self.db, dict(op='reserve', pool='p', id='r', amount=70, rack='a', expires=100,
                               independent=True, plan_id='plan'))
        pool.run(self.db, dict(op='commit', pool='p', id='r', now=10))
        claim.run(self.db, dict(op='bind', id='b1', claim='V', reservation='r',
                                workload='app', node_region='east'))
        result = self.freeze()
        self.assertEqual(result['decision'], 'frozen')
        self.assertEqual(result['binding_token'], 1)
        warrant = self.db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?', ('w1',)).fetchone()
        self.assertEqual((warrant['point_in_time'], warrant['byte_start'], warrant['byte_end'],
                          warrant['classification'], warrant['expires_at']),
                         (20, 56, 60, 'confidential', 100))
        # A later unbind bumps the binding token but the warrant keeps the frozen one.
        claim.run(self.db, dict(op='unbind', id='b1'))
        warrant = self.db.execute('SELECT * FROM legal_warrants WHERE warrant_id=?', ('w1',)).fetchone()
        self.assertEqual(warrant['binding_token'], 1)

    def test_duplicate_external_request_cannot_open_two_warrants(self):
        self.freeze()
        duplicate = self.freeze(warrant='w1-copy', request_key='req-1')
        self.assertEqual(duplicate['reason'], 'duplicate_request')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM legal_warrants').fetchone()[0], 1)

    def test_recipient_below_warrant_clearance_is_rejected(self):
        result = self.freeze(classification='top_secret', request_key='req-secret')
        self.assertEqual(result['reason'], 'recipient_clearance_below_warrant')

    def test_expired_or_malformed_terms_are_rejected(self):
        self.assertEqual(self.freeze(expires_at=25, now=25, request_key='req-exp')['reason'],
                         'invalid_warrant_terms')
        self.assertEqual(self.freeze(byte_range=(60, 60), request_key='req-range')['reason'],
                         'invalid_byte_range')


class HistoricalPrefixTest(LegalProductionBase):
    def test_full_chain_basis_before_invalidation(self):
        self.freeze()
        result = self.prepare('d1', 'sealed_page')
        self.assertEqual(result['decision'], 'prepared')
        self.assertEqual(result['basis']['basis_mode'], 'full_chain')
        self.assertEqual(result['basis']['snapshot_id'], 'S2')

    def test_invalidated_ancestor_is_rescued_by_independent_signed_pages(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        result = self.prepare('d1', 'sealed_page')
        self.assertEqual(result['basis']['basis_mode'], 'attested_prefix')
        self.assertEqual(result['basis']['chain_break_at'], 'S1')
        self.assertEqual(result['basis']['attestations'], ['att7'])

    def test_without_attestation_broken_ancestor_blocks_delivery(self):
        self.db.execute('DELETE FROM legal_attestations')
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.db.execute('DELETE FROM legal_attestations')
        self.freeze()
        result = self.prepare('d1', 'sealed_page')
        self.assertEqual(result['reason'], 'historical_prefix_unprovable')

    def test_tampered_attestation_chain_is_rejected(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        # A second attestation whose prev_hash does not extend the chain.
        bad = dict(op='register_attestation', id='att-bad', controller='independent-controller',
                   claim='V', point_in_time=21, page_no=7, snapshot='S2',
                   data_hash=hashlib.sha256(PAGE7).hexdigest(),
                   prev_hash='deadbeef' * 8, signature='00' * 64)
        self.assertEqual(lp.run(self.db, bad)['reason'], 'attestation_chain_broken')

    def test_newer_generation_can_never_backfill_old_history(self):
        # S3 confirmed at point 40 must not serve a point-20 warrant.
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        recovery.run(self.db, dict(op='snapshot', id='S3', claim='V', parent='S2', generation=3))
        lp.run(self.db, dict(op='register_page_evidence', id='ev7-s3', snapshot='S3', claim='V', page_no=7, data_hex=bytes([0]*8).hex(), confirmed_at=40, segments=[[0,8,'scopeA']]))
        self.freeze()
        result = self.prepare('d1', 'sealed_page')
        self.assertEqual(result['basis']['snapshot_id'], 'S2')
        self.assertNotIn('S3', json.dumps(result['basis']))

    def test_point_before_any_confirmation_has_no_deliverable_prefix(self):
        self.freeze(request_key='req-early', point_in_time=5, warrant='w-early')
        self.assertEqual(self.prepare('d-early', 'sealed_page', warrant='w-early')['reason'],
                         'historical_prefix_unprovable')

    def test_attestation_only_rescue_when_snapshot_itself_invalidated(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S2'))
        self.freeze(request_key='req-s2')
        result = self.prepare('d1', 'sealed_page')
        self.assertEqual(result['basis']['basis_mode'], 'attestation_only')
        self.assertEqual(result['basis']['snapshot_id'], 'S2')


class SealedPageRouteTest(LegalProductionBase):
    def test_court_gets_ciphertext_full_page_and_others_only_proofs(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        self.prepare('d1', 'sealed_page')
        seal = lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        self.assertEqual(seal['decision'], 'sealed')
        # Court decrypts the exact historical full page (A and B together).
        self.assertEqual(self.open_artifact('d1', 'court', 'sealed_page'), PAGE7)
        # Agent receives only a range/hash proof, never page bytes.
        proof = json.loads(self.open_artifact('d1', 'agent', 'range_proof'))
        self.assertEqual(proof['page_hashes']['7'], hashlib.sha256(PAGE7).hexdigest())
        self.assertIn(7, proof['foreign_pages'])
        serialized = json.dumps(proof)
        self.assertNotIn(PAGE7.hex(), serialized)
        self.assertNotIn(B_BYTES.hex(), serialized)
        # No readable page content exists in any stored artifact blob.
        self.assertNotIn(B_BYTES, self.all_blob_bytes())
        self.assertNotIn(A_BYTES, self.all_blob_bytes())
        # The sealed blob is not itself plaintext.
        row = self.db.execute("SELECT content FROM legal_artifacts WHERE artifact_id='d1:court:sealed_page'").fetchone()
        self.assertNotIn(PAGE7, bytes(row['content']))

    def test_sealed_page_cannot_be_opened_with_wrong_or_rotated_context(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        self.prepare('d1', 'sealed_page')
        lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        row = self.db.execute("SELECT * FROM legal_artifacts WHERE artifact_id='d1:court:sealed_page'").fetchone()
        with self.assertRaises(ValueError):
            lp.open_artifact(COURT_SECRET, 'd1:court:sealed_page:999', bytes(row['content']))
        with self.assertRaises(ValueError):
            lp.open_artifact(AGENT_SECRET, 'd1:court:sealed_page:1', bytes(row['content']))


class RedactedRebuildRouteTest(LegalProductionBase):
    def test_redacted_delivery_contains_only_A_and_sealed_full_page_commitment(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        self.prepare('d2', 'redacted_rebuild')
        lp.run(self.db, dict(op='seal_delivery', id='d2', now=27))
        # Court's readable document is exactly the A history bytes.
        self.assertEqual(self.open_artifact('d2', 'court', 'redacted_document'), A_BYTES)
        # Court alone also holds the sealed commitment of the full page.
        self.assertEqual(self.open_artifact('d2', 'court', 'page_commitment'), PAGE7)
        # Agent's redacted view exposes A but never B.
        view = json.loads(self.open_artifact('d2', 'agent', 'redacted_view'))
        self.assertEqual(view['in_scope_bytes_hex'], A_BYTES.hex())
        self.assertEqual(view['masked_pages'], [7])
        self.assertNotIn(B_BYTES.hex(), json.dumps(view))
        # B exists only inside the court-held sealed commitment, nowhere readable.
        readable = self.open_artifact('d2', 'court', 'redacted_document') + \
            json.dumps(view).encode('utf-8')
        self.assertNotIn(B_BYTES, readable)

    def test_both_routes_are_executable_under_one_warrant_and_differ_in_custody(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        self.prepare('d-sealed', 'sealed_page')
        self.prepare('d-redacted', 'redacted_rebuild')
        lp.run(self.db, dict(op='seal_delivery', id='d-sealed', now=27))
        lp.run(self.db, dict(op='seal_delivery', id='d-redacted', now=27))
        # Court-readable content differs by route: ciphertext vs redacted plaintext.
        sealed_kind = self.db.execute(
            "SELECT kind FROM legal_artifacts WHERE delivery_id='d-sealed' AND recipient_id='court'").fetchall()
        redacted_kinds = self.db.execute(
            "SELECT kind FROM legal_artifacts WHERE delivery_id='d-redacted' AND recipient_id='court'").fetchall()
        self.assertEqual([r['kind'] for r in sealed_kind], ['sealed_page'])
        self.assertEqual(sorted(r['kind'] for r in redacted_kinds),
                         ['page_commitment', 'redacted_document'])
        # Both deliver the true A history bytes.
        self.assertEqual(self.open_artifact('d-sealed', 'court', 'sealed_page')[:4], A_BYTES)
        self.assertEqual(self.open_artifact('d-redacted', 'court', 'redacted_document'), A_BYTES)


class LifecycleAndIdempotencyTest(LegalProductionBase):
    def test_every_stage_is_idempotent_and_never_duplicates_delivery(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        first = self.prepare('d1', 'sealed_page')
        again = self.prepare('d1', 'sealed_page')
        self.assertEqual(again['decision'], 'reused')
        other_id = self.prepare('d1-other', 'sealed_page')
        self.assertEqual(other_id['delivery'], 'd1')
        seal_1 = lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        seal_2 = lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        self.assertEqual(seal_1['artifacts'], seal_2['artifacts'])
        notify_1 = lp.run(self.db, dict(op='notify_delivery', id='d1', now=28))
        notify_2 = lp.run(self.db, dict(op='notify_delivery', id='d1', now=28))
        self.assertEqual(notify_1['notifications'], notify_2['notifications'])
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_artifacts WHERE delivery_id='d1'").fetchone()[0], 2)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_notifications WHERE delivery_id='d1'").fetchone()[0], 2)
        self.assertEqual(first['delivery'], 'd1')

    def test_notify_before_seal_is_blocked(self):
        self.freeze()
        self.prepare('d1', 'sealed_page')
        self.assertEqual(lp.run(self.db, dict(op='notify_delivery', id='d1', now=28))['reason'],
                         'delivery_not_sealed')

    def test_expired_warrant_blocks_prepare_and_seal(self):
        self.freeze(expires_at=30)
        self.assertEqual(self.prepare('d1', 'sealed_page', now=31)['reason'], 'warrant_expired')
        # A timely prepare followed by a late seal is also blocked.
        self.assertEqual(self.prepare('d2', 'redacted_rebuild', now=26)['decision'], 'prepared')
        self.assertEqual(lp.run(self.db, dict(op='seal_delivery', id='d2', now=31))['reason'],
                         'warrant_expired')


class KeyRotationTest(LegalProductionBase):
    def test_rotation_pins_new_seals_to_the_new_key_and_keeps_old_grants(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        self.prepare('d1', 'sealed_page')
        lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        rotate = lp.run(self.db, dict(op='rotate_recipient_key', id='court-key-2',
                                      recipient='court', secret_hex='ee' * 32))
        self.assertEqual(rotate['version'], 2)
        # Existing artifact and grant stay bound to the original key generation.
        old = self.db.execute(
            "SELECT key_id FROM legal_artifacts WHERE artifact_id='d1:court:sealed_page'").fetchone()
        self.assertEqual(old['key_id'], 'court-key')
        # A new delivery seals under the rotated key.
        self.freeze(warrant='w2', request_key='req-2')
        self.prepare('d2', 'sealed_page', warrant='w2', now=30)
        lp.run(self.db, dict(op='seal_delivery', id='d2', now=31))
        new = self.db.execute(
            "SELECT key_id FROM legal_artifacts WHERE artifact_id='d2:court:sealed_page'").fetchone()
        self.assertEqual(new['key_id'], 'court-key-2')

    def test_revoked_key_blocks_new_seals_until_a_new_key_exists(self):
        self.freeze()
        lp.run(self.db, dict(op='revoke_recipient_key', id='agent-key'))
        self.prepare('d1', 'sealed_page')
        self.assertEqual(lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))['reason'],
                         'recipient_key_unavailable')
        lp.run(self.db, dict(op='register_recipient_key', id='agent-key-2', recipient='agent',
                             secret_hex='ef' * 32, clearance='confidential'))
        self.assertEqual(lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))['decision'],
                         'sealed')


class InterruptionTest(LegalProductionBase):
    def test_in_database_staging_is_removed_in_the_seal_transaction(self):
        self.freeze()
        self.prepare('d1', 'sealed_page')
        # Prepared staging exists, but contains no foreign-readable artifact yet.
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_staging WHERE delivery_id='d1'").fetchone()[0], 2)
        lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM legal_staging').fetchone()[0], 0)

    def test_filesystem_crash_leaves_only_0600_staging_that_recovery_shreds(self):
        workspace = tempfile.mkdtemp(dir=self.tmp.name)
        self.freeze()
        with self.assertRaises(RuntimeError):
            self.prepare('d1', 'sealed_page', workspace=workspace, _fail_after_staging=True)
        # The evidence transaction rolled back: no delivery persisted.
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_deliveries WHERE delivery_id='d1'").fetchone()[0], 0)
        surviving = []
        found_plaintext_page = False
        for root, _, files in os.walk(workspace):
            for name in files:
                path = os.path.join(root, name)
                surviving.append(path)
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                with open(path, 'rb') as handle:
                    if PAGE7 in handle.read():
                        found_plaintext_page = True
        self.assertTrue(surviving)
        # The full mixed page (including B) only ever exists as a 0600 staging file.
        self.assertTrue(found_plaintext_page)
        recovery_report = lp.recover_workspace(self.db, workspace)
        self.assertEqual(len(recovery_report['reaped_folders']), 1)
        self.assertEqual(os.listdir(workspace), [])
        # Retry succeeds and produces exactly one delivery, no duplicate.
        result = self.prepare('d1', 'sealed_page')
        self.assertEqual(result['decision'], 'prepared')
        lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_deliveries WHERE delivery_id='d1'").fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM legal_staging').fetchone()[0], 0)

    def test_abort_purges_staging_and_allows_a_fresh_prepare(self):
        workspace = tempfile.mkdtemp(dir=self.tmp.name)
        self.freeze()
        self.prepare('d1', 'sealed_page', workspace=workspace)
        self.assertEqual(lp.run(self.db, dict(op='abort_delivery', id='d1'))['decision'], 'aborted')
        self.assertEqual(os.listdir(workspace), [])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM legal_staging').fetchone()[0], 0)
        self.assertEqual(self.prepare('d2', 'sealed_page')['decision'], 'prepared')


class WithdrawalAndRedeliveryTest(LegalProductionBase):
    def _deliver_and_receipt(self, delivery='d2', route='redacted_rebuild'):
        self.freeze()
        self.prepare(delivery, route)
        lp.run(self.db, dict(op='seal_delivery', id=delivery, now=27))
        lp.run(self.db, dict(op='notify_delivery', id=delivery, now=28))
        self.receipt_all(delivery)

    def test_review_detects_late_invalidation_without_overwriting_receipts(self):
        self._deliver_and_receipt()
        # Snapshot invalidation arrives after the delivery was already receipted.
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        review = lp.run(self.db, dict(op='review_evidence', id='d2', now=40))
        self.assertEqual(review['decision'], 'impaired')
        self.assertEqual(review['sealed_basis']['basis_mode'], 'full_chain')
        self.assertEqual(review['current_basis']['basis_mode'], 'attested_prefix')
        # Original artifacts, receipts and notifications remain intact.
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_artifacts WHERE delivery_id='d2'").fetchone()[0], 3)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_receipts WHERE delivery_id='d2'").fetchone()[0], 3)

    def test_withdrawal_records_flow_and_revokes_only_route_scoped_grants(self):
        self._deliver_and_receipt()
        result = lp.run(self.db, dict(op='withdraw_delivery', id='d2', withdrawal_id='wd1',
                                      reason='source_invalidated', now=41))
        self.assertEqual(result['revoked_scopes'], ['page_commitment'])
        # The readable redacted document grant survives; only the sealed
        # commitment of the full (B-bearing) page is revoked.
        self.assertEqual(self.db.execute(
            "SELECT state FROM legal_decryption_grants WHERE delivery_id='d2' AND scope='page_commitment'"
        ).fetchone()[0], 'revoked')
        self.assertEqual(self.db.execute(
            "SELECT state FROM legal_decryption_grants WHERE delivery_id='d2' AND scope='redacted_document'"
        ).fetchone()[0], 'active')
        # Old artifact flow and receipts are preserved.
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_artifacts WHERE delivery_id='d2'").fetchone()[0], 3)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM legal_withdrawals WHERE withdrawal_id='wd1'").fetchone()[0], 1)
        self.assertEqual(lp.run(self.db, dict(op='withdraw_delivery', id='d2', withdrawal_id='wd1',
                                              reason='x', now=41))['decision'], 'reused')

    def test_sealed_route_withdrawal_revokes_court_decryption_right(self):
        self._deliver_and_receipt(delivery='d1', route='sealed_page')
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        result = lp.run(self.db, dict(op='withdraw_delivery', id='d1', withdrawal_id='wd1',
                                      reason='source_invalidated', now=41))
        self.assertEqual(result['revoked_scopes'], ['sealed_page', 'range_proof'])
        self.assertEqual(self.db.execute(
            "SELECT state FROM legal_decryption_grants WHERE delivery_id='d1' AND scope='sealed_page'"
        ).fetchone()[0], 'revoked')

    def test_supplemental_warrant_redelivers_exact_history_after_withdrawal(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self._deliver_and_receipt()
        lp.run(self.db, dict(op='withdraw_delivery', id='d2', withdrawal_id='wd1',
                             reason='source_invalidated', now=41))
        lp.run(self.db, dict(op='register_recipient_key', id='court-key-2', recipient='court',
                             secret_hex='ff' * 32, clearance='secret'))
        reissue = lp.run(self.db, dict(op='reissue_warrant', id='w2', request_key='req-2',
                                       predecessor='w1', expires_at=200, now=42))
        self.assertEqual(reissue['decision'], 'frozen')
        redelivery = self.prepare('d4', 'redacted_rebuild', warrant='w2', now=43)
        self.assertEqual(redelivery['basis']['basis_mode'], 'attested_prefix')
        lp.run(self.db, dict(op='seal_delivery', id='d4', now=44))
        self.assertEqual(self.open_artifact('d4', 'court', 'redacted_document'), A_BYTES)
        # The predecessor chain and both delivery flows are retained.
        self.assertEqual(self.db.execute(
            "SELECT predecessor_id FROM legal_warrants WHERE warrant_id='w2'").fetchone()[0], 'w1')
        self.assertEqual(self.db.execute(
            "SELECT state FROM legal_deliveries WHERE delivery_id='d2'").fetchone()[0], 'withdrawn')
        self.assertEqual(self.db.execute(
            "SELECT state FROM legal_deliveries WHERE delivery_id='d4'").fetchone()[0], 'sealed')

    def test_reissue_requires_a_withdrawn_predecessor(self):
        self._deliver_and_receipt()
        result = lp.run(self.db, dict(op='reissue_warrant', id='w2', request_key='req-2',
                                      predecessor='w1', expires_at=200, now=42))
        self.assertEqual(result['reason'], 'predecessor_not_withdrawn')


class SealedImmutabilityTest(LegalProductionBase):
    def test_later_writes_and_snapshot_invalidation_never_rewrite_sealed_bytes(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        recovery.run(self.db, dict(op='snapshot', id='S3', claim='V', parent='S2', generation=3))
        lp.run(self.db, dict(op='register_page_evidence', id='ev7-s3', snapshot='S3', claim='V', page_no=7, data_hex=bytes([0]*8).hex(), confirmed_at=40, segments=[[0,8,'scopeA']]))
        self.freeze()
        self.prepare('d2', 'redacted_rebuild')
        lp.run(self.db, dict(op='seal_delivery', id='d2', now=27))
        sealed_hash = self.db.execute(
            "SELECT content_hash FROM legal_artifacts WHERE artifact_id='d2:court:redacted_document'"
        ).fetchone()[0]
        # Unbind, promotion-style churn and further invalidations happen after sealing.
        claim.run(self.db, dict(op='declare', id='other', size=10, mode='single_writer', region='east'))
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S2'))
        # Sealed artifact hash, delivery basis and receipts are untouched.
        self.assertEqual(self.db.execute(
            "SELECT content_hash FROM legal_artifacts WHERE artifact_id='d2:court:redacted_document'"
        ).fetchone()[0], sealed_hash)
        basis = json.loads(self.db.execute(
            "SELECT basis FROM legal_deliveries WHERE delivery_id='d2'").fetchone()[0])
        self.assertEqual(basis['snapshot_id'], 'S2')
        review = lp.run(self.db, dict(op='review_evidence', id='d2', now=50))
        self.assertIn(review['decision'], ('impaired', 'compromised'))
        self.assertEqual(self.open_artifact('d2', 'court', 'redacted_document'), A_BYTES)

    def test_conflicting_page_evidence_cannot_silently_replace_registered_page(self):
        result = lp.run(self.db, dict(op='register_page_evidence', id='ev7b', snapshot='S2',
                                      claim='V', page_no=7, data_hex=bytes([1] * 8).hex(),
                                      confirmed_at=22, segments=[[0, 8, 'scopeA']]))
        self.assertEqual(result['reason'], 'page_evidence_conflict')


class ReplayTest(LegalProductionBase):
    def test_full_evidence_replay_rebuilds_every_legal_table(self):
        recovery.run(self.db, dict(op='invalidate_snapshot', id='S1'))
        self.freeze()
        self.prepare('d1', 'sealed_page')
        lp.run(self.db, dict(op='seal_delivery', id='d1', now=27))
        lp.run(self.db, dict(op='notify_delivery', id='d1', now=28))
        self.receipt_all('d1')
        db_path = self.db.execute('PRAGMA database_list').fetchone()[2]
        self.db.close()
        result = replay(db_path, {'pool': pool, 'claim': claim, 'recovery': recovery,
                                  'legal': lp})
        self.assertTrue(result['verified'], result['divergences'])
        self.assertGreater(result['decision_count'], 8)


if __name__ == '__main__':
    unittest.main()
