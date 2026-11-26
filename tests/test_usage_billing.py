import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, report, replay
from cloudlab import claim
from cloudlab.usage_capture import capture_page, provisional_invoice
from cloudlab import usage_billing as ub

READ_RATE, WRITE_RATE = 2, 5
PERIOD = 10
RECON = 'recon:V:10'


def page(gateway, generation, reads, writes, raw=None, corrupted=()):
    return dict(claim='V', period=PERIOD, gateway=gateway, generation=generation,
                window=[0, 600], reads=reads, writes=writes,
                raw=raw or ('bytes-' + gateway), corrupted_ops=list(corrupted))


def action(request_id, op, stage='acknowledged', kind='customer',
           period=PERIOD, gateway=None, page_id=None):
    payload = dict(request_id=request_id, claim='V', period=period, op=op,
                   kind=kind, stage=stage, gateway=gateway, page=page_id)
    return payload


class UsageBillingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / 'billing.sqlite'))
        claim.run(self.db, dict(op='declare', id='V', size=4,
                                mode='single_writer', region='east'))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _headline(self):
        """账期第 10 分钟：G1 读100/写20，G2 接管后读80/写20，客户持有20个写收讫。"""
        self.assertEqual(ub.ingest_page(self.db, 'p-g1', page('G1', 1, 100, 20))
                         ['decision'], 'received')
        self.assertEqual(ub.ingest_page(self.db, 'p-g2', page('G2', 2, 80, 20))
                         ['decision'], 'received')
        for i in range(20):
            self.assertEqual(
                ub.record_action(self.db, action('w-%02d' % i, 'write'))['decision'],
                'recorded')
        return ub.reconcile(self.db, RECON, 'V', PERIOD)

    def test_two_verified_pages_keep_provable_bounds_not_a_sum(self):
        result = self._headline()
        reads, writes = result['ops']['read'], result['ops']['write']
        # 读没有逐请求身份：下界是任一单页的最大值，上界才是两页之和。
        self.assertEqual((reads['lower_bound'], reads['upper_bound']), (100, 180))
        # 20 个客户收讫证实至少 20 次唯一写；G2 的 20 次是否与 G1 同批无法判定。
        self.assertEqual((writes['lower_bound'], writes['upper_bound']), (20, 40))
        self.assertEqual(writes['proven_ids'], 20)
        self.assertEqual(writes['bounds_state'], 'provisional_bounds')
        self.assertNotIn(180, (reads['lower_bound'],))
        self.assertNotIn(40, (writes['lower_bound'],))

    def test_provisional_invoice_still_overcharges_but_bounded_bill_does_not(self):
        self._headline()
        # 旧的暂收发票直接合计所有页：180 读、40 写（演示其过度收费）。
        legacy = [{'claim': 'V', 'period': PERIOD, 'reads': 100, 'writes': 20},
                  {'claim': 'V', 'period': PERIOD, 'reads': 80, 'writes': 20}]
        self.assertEqual(capture_page(self.db, 'legacy', legacy)['decision'], 'captured')
        naive = provisional_invoice(self.db, 'legacy-inv', 'V', READ_RATE, WRITE_RATE)
        self.assertEqual(naive['amount'], 180 * READ_RATE + 40 * WRITE_RATE)
        # 封顶暂收账单只就下界收费：100 读、20 写，余量进争议保留。
        capped = ub.issue_bill(self.db, dict(
            id='cap', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE))
        self.assertEqual(capped['confirmed_amount'], 100 * READ_RATE + 20 * WRITE_RATE)
        self.assertEqual(capped['disputed_amount'],
                         80 * READ_RATE + 20 * WRITE_RATE)
        self.assertEqual(capped['balance_due'], capped['confirmed_amount'])

    def test_hold_path_has_no_payable_and_capped_path_has_adjustable_payable(self):
        self._headline()
        hold = ub.issue_bill(self.db, dict(
            id='hold', claim='V', period=PERIOD, mode='hold',
            read_rate=READ_RATE, write_rate=WRITE_RATE))
        self.assertEqual(hold['state'], 'under_review')
        self.assertEqual(hold['confirmed_amount'], 0)
        self.assertEqual(hold['balance_due'], 0)
        report0 = ub.settlement_report(self.db, 'V', PERIOD)
        self.assertEqual(report0['payable_now'], 0)
        self.assertEqual(report0['pending_units'], {'read': 80, 'write': 20})
        cap = ub.issue_bill(self.db, dict(
            id='cap', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE))
        self.assertEqual(cap['state'], 'payable')
        report1 = ub.settlement_report(self.db, 'V', PERIOD)
        self.assertEqual(report1['payable_now'], cap['confirmed_amount'])

    def test_page_bytes_window_and_generation_are_immutable(self):
        ub.ingest_page(self.db, 'p', page('G1', 1, 5, 5))
        # 同 id 原样重放幂等。
        self.assertEqual(ub.ingest_page(self.db, 'p', page('G1', 1, 5, 5))
                         ['decision'], 'reused')
        # 改原始字节、窗口或网关代次都不能覆盖已接收原件。
        tampered = page('G1', 1, 5, 5, raw='different-bytes')
        self.assertEqual(ub.ingest_page(self.db, 'p', tampered)['reason'],
                         'immutable_page_conflict')
        newer = page('G1', 2, 5, 5)
        self.assertEqual(ub.ingest_page(self.db, 'p', newer)['reason'],
                         'immutable_page_conflict')
        row = self.db.execute('SELECT raw_digest, generation FROM gw_pages WHERE id=?',
                              ('p',)).fetchone()
        self.assertEqual(row['generation'], 1)

    def test_cross_page_duplicates_decided_by_action_identity_not_summary(self):
        ub.ingest_page(self.db, 'p-g1', page('G1', 1, 0, 20))
        ub.ingest_page(self.db, 'p-g2', page('G2', 2, 0, 20))
        # 逐动作原件证明 G2 的 20 次写与 G1 是同一批身份。
        for i in range(20):
            rid = 'same-w-%02d' % i
            ub.record_action(self.db, action(rid, 'write', gateway='G1',
                                             page_id='p-g1'))
            ub.record_action(self.db, action(rid, 'write', gateway='G2',
                                             page_id='p-g2'))
        result = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(result['ops']['write']['lower_bound'], 20)
        self.assertEqual(result['ops']['write']['upper_bound'], 20)
        self.assertEqual(result['ops']['write']['bounds_state'], 'exact')

    def test_distinct_g2_writes_allow_supplemental_charge_within_bounds(self):
        self._headline()
        cap = ub.issue_bill(self.db, dict(
            id='cap', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE))
        # 旧网关日志恢复：G2 的 20 次写是全新身份，唯一写达到上界 40。
        for i in range(20):
            ub.record_action(self.db, action('g2-new-%02d' % i, 'write',
                                             gateway='G2', page_id='p-g2'))
        ub.reconcile(self.db, RECON, 'V', PERIOD)
        posted = ub.correct_bill(self.db, dict(
            id='cor-add', bill='cap', kind='supplemental', op='write', units=20,
            evidence_ref=RECON + ':write', reason='g1 logs recovered: distinct writes'))
        self.assertEqual(posted['decision'], 'posted')
        self.assertEqual(posted['amount'], 20 * WRITE_RATE)
        self.assertEqual(posted['units_after'], 40)
        self.assertEqual(posted['balance_due'],
                         cap['confirmed_amount'] + 20 * WRITE_RATE)
        # 再补一笔就越过对账上界，拒绝。
        self.assertEqual(ub.correct_bill(self.db, dict(
            id='cor-too-much', bill='cap', kind='supplemental', op='write',
            units=1, evidence_ref=RECON + ':write'))['reason'],
            'correction_outside_bounds')
        # 无原凭证的调账拒绝。
        self.assertEqual(ub.correct_bill(self.db, dict(
            id='cor-noref', bill='cap', kind='supplemental', op='write',
            units=1, evidence_ref='does-not-exist'))['reason'],
            'unknown_evidence_ref')

    def test_reversal_after_payment_never_double_charges(self):
        # 单页场景：先按可证实下界 20 次写封顶暂收并付清。
        ub.ingest_page(self.db, 'p-g1', page('G1', 1, 100, 20))
        for i in range(20):
            ub.record_action(self.db, action('w-%02d' % i, 'write',
                                             gateway='G1', page_id='p-g1'))
        ub.reconcile(self.db, RECON, 'V', PERIOD)
        ub.issue_bill(self.db, dict(
            id='cap', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE))
        confirmed = 100 * READ_RATE + 20 * WRITE_RATE
        self.assertEqual(ub.apply_payment(self.db, 'cap', confirmed)['state'],
                         'settled')
        # 旧网关原始日志恢复：逐动作原件证明 w-19 是一次内部重试被误计入客户页，
        # 真实客户唯一写只有 19 次，对账下界随原件下移。
        self.assertEqual(ub.reclassify_action(
            self.db, 'w-19', 'retry', 'retry mis-billed')['decision'],
            'reclassified')
        refreshed = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(refreshed['ops']['write']['lower_bound'], 19)
        # 冲正必须引用被误计的请求原件；更正 id 重放幂等，不重复入账。
        payload = dict(id='cor-rev', bill='cap', kind='reversal', op='write',
                       units=1, evidence_ref='w-19', reason='retry mis-billed')
        first = ub.correct_bill(self.db, payload)
        again = ub.correct_bill(self.db, payload)
        self.assertEqual(first['decision'], 'posted')
        self.assertEqual(again['decision'], 'reused')
        self.assertEqual(again['balance_after'], first['balance_due'])
        self.assertEqual(first['amount'], -1 * WRITE_RATE)
        self.assertEqual(first['customer_credit'], WRITE_RATE)
        corrections = ub.settlement_report(self.db, 'V', PERIOD)['corrections']
        self.assertEqual(len([c for c in corrections if c['id'] == 'cor-rev']), 1)
        # 继续冲正到对账下界之下会被拒绝，客户不会为“不存在的动作”担责。
        too_far = dict(id='cor-rev-far', bill='cap', kind='reversal',
                       op='write', units=19, evidence_ref='w-00')
        self.assertEqual(ub.correct_bill(self.db, too_far)['reason'],
                         'correction_outside_bounds')

    def test_cross_period_retry_merges_into_original_request(self):
        # 请求在账期 9 被接收，账期 10 由新网关重试并收讫。
        ub.ingest_page(self.db, 'p9', dict(claim='V', period=9, gateway='G1',
                                           generation=1, window=[0, 600],
                                           reads=0, writes=1, raw='p9'))
        first = ub.record_action(self.db, action(
            'retry-w', 'write', stage='gateway_received', period=9,
            gateway='G1', page_id='p9'))
        self.assertEqual(first['decision'], 'recorded')
        merged = ub.record_action(self.db, action(
            'retry-w', 'write', stage='acknowledged', kind='retry',
            period=PERIOD, gateway='G2'))
        self.assertEqual(merged['decision'], 'merged')
        self.assertTrue(merged['cross_period_retry'])
        self.assertEqual(merged['period'], 9)
        # 账期 10 的对账里看不到这次重试，它仍归属账期 9 的请求原件。
        ub.ingest_page(self.db, 'p10', page('G2', 2, 0, 0))
        result = ub.reconcile(self.db, 'recon:V:10', 'V', PERIOD)
        self.assertEqual(result['ops']['write']['proven_ids'], 0)
        # 非重试事件冒用同一身份跨账期，拒绝。
        self.assertEqual(ub.record_action(self.db, action(
            'retry-w', 'write', period=11, kind='customer'))['reason'],
            'request_identity_conflict')

    def test_acknowledgement_arriving_after_page_still_proves_identity(self):
        ub.ingest_page(self.db, 'p-g1', page('G1', 1, 0, 20))
        before = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(before['ops']['write']['proven_ids'], 0)
        self.assertEqual(before['ops']['write']['bounds_state'], 'provisional_bounds')
        # 页面已封存后，客户收讫才到齐，证据追加而不改动页面原件。
        for i in range(20):
            ub.record_action(self.db, action('late-%02d' % i, 'write'))
        after = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(after['ops']['write']['lower_bound'], 20)
        self.assertEqual(after['ops']['write']['proven_ids'], 20)
        page_row = self.db.execute(
            'SELECT raw_digest FROM gw_pages WHERE id=?', ('p-g1',)).fetchone()
        self.assertTrue(page_row['raw_digest'])

    def test_partially_corrupted_gateway_page_keeps_provable_bounds(self):
        ub.ingest_page(self.db, 'p-g1', page('G1', 1, 100, 20))
        # G2 的写原件损坏，读原件仍可用：损坏总数退出对账但页保留。
        self.assertEqual(ub.ingest_page(
            self.db, 'p-g2', page('G2', 2, 80, 20, corrupted=('write',))
        )['decision'], 'received')
        result = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(result['ops']['write']['corrupted_pages'], ['p-g2'])
        self.assertEqual((result['ops']['read']['lower_bound'],
                          result['ops']['read']['upper_bound']), (100, 180))
        # 写只能依据未损坏的 G1 页给出边界，绝不拿损坏总数凑数。
        self.assertEqual((result['ops']['write']['lower_bound'],
                          result['ops']['write']['upper_bound']), (20, 20))
        self.assertEqual(result['ops']['write']['bounds_state'], 'provisional_bounds')

    def test_multiple_success_receipts_collapse_to_one_chargeable_action(self):
        ub.ingest_page(self.db, 'p', page('G1', 1, 0, 1))
        for _ in range(3):
            r = ub.record_action(self.db, action('once', 'write'))
        self.assertEqual(r['decision'], 'merged')
        self.assertEqual(r['receipt_count'], 3)
        result = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(result['ops']['write']['proven_ids'], 1)
        rows = self.db.execute(
            'SELECT COUNT(*) FROM action_evidence WHERE request_id=?',
            ('once',)).fetchone()[0]
        self.assertEqual(rows, 1)

    def test_internal_sync_retries_and_probes_are_never_billed(self):
        ub.ingest_page(self.db, 'p', page('G2', 2, 10, 10))
        for i in range(5):
            ub.record_action(self.db, action('sync-%d' % i, 'write',
                                             kind='replica_sync'))
            ub.record_action(self.db, action('probe-%d' % i, 'read',
                                             kind='recovery_probe'))
        ub.record_action(self.db, action('rt', 'write', kind='retry'))
        result = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(result['ops']['write']['proven_ids'], 0)
        self.assertEqual(result['ops']['read']['proven_ids'], 0)
        summary = ub.settlement_report(self.db, 'V', PERIOD)
        self.assertEqual(summary['internal_actions_excluded'], 11)

    def test_shared_volume_isolates_customers_by_claim_identity(self):
        claim.run(self.db, dict(op='declare', id='W', size=2,
                                mode='single_writer', region='east'))
        ub.ingest_page(self.db, 'p-v', page('G1', 1, 10, 10))
        other = dict(claim='W', period=PERIOD, gateway='G1', generation=1,
                     window=[0, 600], reads=7, writes=3, raw='bytes-W')
        self.assertEqual(ub.ingest_page(self.db, 'p-w', other)['decision'],
                         'received')
        # 属于 W 的动作证据不能挂到 V 的页面上。
        stray = ub.record_action(self.db, dict(
            request_id='stray', claim='W', period=PERIOD, op='write',
            kind='customer', stage='acknowledged', page='p-v'))
        self.assertEqual(stray['reason'], 'page_identity_conflict')
        v = ub.reconcile(self.db, RECON, 'V', PERIOD)
        w = ub.reconcile(self.db, 'recon:W:10', 'W', PERIOD)
        self.assertEqual((v['ops']['read']['lower_bound'],
                          v['ops']['write']['lower_bound']), (10, 10))
        self.assertEqual((w['ops']['read']['lower_bound'],
                          w['ops']['write']['lower_bound']), (7, 3))

    def test_discount_and_paid_amounts_are_separated_from_confirmed(self):
        self._headline()
        issued = ub.issue_bill(self.db, dict(
            id='cap', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE, discount=30))
        self.assertEqual(issued['discount_amount'], 30)
        self.assertEqual(issued['balance_due'],
                         issued['confirmed_amount'] - 30)
        kinds = {r['kind'] for r in self.db.execute(
            'SELECT DISTINCT kind FROM bill_lines WHERE bill_id=?', ('cap',))}
        self.assertEqual(kinds, {'confirmed', 'disputed_hold', 'discount'})
        # 优惠不能超过确定收费。
        self.assertEqual(ub.issue_bill(self.db, dict(
            id='cap2', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE,
            discount=issued['confirmed_amount'] + 1))['reason'],
            'discount_exceeds_confirmed')

    def test_bill_and_reconciliation_are_idempotent_and_evidence_backed(self):
        self._headline()
        payload = dict(id='cap', claim='V', period=PERIOD, mode='capped',
                       read_rate=READ_RATE, write_rate=WRITE_RATE)
        first = ub.issue_bill(self.db, payload)
        second = ub.issue_bill(self.db, payload)
        self.assertEqual(second['decision'], 'reused')
        self.assertEqual(second['balance_due'], first['balance_due'])
        # 重新对账刷新边界但不制造重复行。
        ub.reconcile(self.db, RECON, 'V', PERIOD)
        rows = self.db.execute(
            'SELECT COUNT(*) FROM reconciliations WHERE substr(id,1,?)=?',
            (len(RECON) + 1, RECON + ':')).fetchone()[0]
        self.assertEqual(rows, 2)
        events = report(self.db)
        self.assertTrue(any(e['event'] == 'reconcile' for e in events))
        self.assertTrue(any(e['event'] == 'issue_bill' for e in events))

    def test_evidence_replays_billing_decisions_table_for_table(self):
        # 全部决策走 audited run()，replay 能从原始事件逐表重建对账与账单状态。
        db_path = str(Path(self.tmp.name) / 'replay.sqlite')
        source = connect(db_path)
        claim.run(source, dict(op='declare', id='V', size=4, mode='single_writer',
                               region='east'))
        source.close()
        steps = [
            dict(command='ingest_page', page_id='g1', claim='V', period=PERIOD,
                 gateway='G1', generation=1, window=[0, 600], reads=100, writes=20,
                 raw='r1'),
            dict(command='ingest_page', page_id='g2', claim='V', period=PERIOD,
                 gateway='G2', generation=2, window=[0, 600], reads=80, writes=20,
                 raw='r2'),
        ]
        for i in range(20):
            steps.append(dict(command='record_action', request_id='w%02d' % i,
                              claim='V', period=PERIOD, op='write', kind='customer',
                              stage='acknowledged'))
        steps += [
            dict(command='reconcile', id=RECON, claim='V', period=PERIOD),
            dict(command='issue_bill', id='bill', claim='V', period=PERIOD,
                 mode='capped', read_rate=READ_RATE, write_rate=WRITE_RATE),
            dict(command='apply_payment', bill='bill', amount=300),
        ]
        source = connect(db_path)
        for step in steps:
            ub.run(source, step)
        source.close()
        result = replay(db_path, {'claim': claim, 'billing': ub})
        self.assertTrue(result['verified'], result['divergences'])
        self.assertGreaterEqual(result['decision_count'], len(steps))

    def test_recovery_promote_traffic_is_excluded_from_customer_requests(self):
        # 恢复提升产生的探针与再同步走内部 kind，不进对账下界。
        ub.ingest_page(self.db, 'p', page('G2', 2, 4, 4))
        ub.record_action(self.db, action('failover-probe', 'read',
                                         kind='recovery_probe',
                                         stage='gateway_received'))
        ub.record_action(self.db, action('failover-sync', 'write',
                                         kind='replica_sync',
                                         stage='executed'))
        result = ub.reconcile(self.db, RECON, 'V', PERIOD)
        self.assertEqual(result['ops']['read']['proven_ids'], 0)
        self.assertEqual(result['ops']['write']['proven_ids'], 0)
        bill = ub.issue_bill(self.db, dict(
            id='cap', claim='V', period=PERIOD, mode='capped',
            read_rate=READ_RATE, write_rate=WRITE_RATE))
        # 仍只按页下界收费，内部动作一个都不加。
        self.assertEqual(bill['confirmed_amount'], 4 * READ_RATE + 4 * WRITE_RATE)


if __name__ == '__main__':
    unittest.main()
