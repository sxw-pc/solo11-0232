"""网关用量对账、可支付账单与后续更正。

故障切换后，多个网关代次会对同一卷、同一账期上报彼此重叠的聚合用量页。
两个都验签通过的页不能简单相加，也不能由最新网关覆盖：页只给总数，给不出
逐动作交集。本模块在 :mod:`cloudlab.usage_capture` 的页摘要之上补齐三类原件：

* 网关页原件（原始字节摘要、采集窗口、网关代次），接收后不可改写；
* 逐动作证据（客户请求、网关接收、后端执行、客户收讫四阶段），按客户请求
  身份去重，内部副本同步、失败重试、恢复探针不产生新请求；
* 账单与更正凭证，确定收费、争议保留、优惠、已付款分开，已发账单只能以
  关联原凭证的补收或冲正改变。

原始逐请求日志不可得时，对账只输出可证明的上下界，绝不编造唯一请求数。
"""
import hashlib
import json

from .store import transaction, record, audit_run

OPS = ('read', 'write')
# 内部流量：副本同步、失败重试、恢复探针，不是客户新请求。
INTERNAL_KINDS = frozenset(('replica_sync', 'retry', 'recovery_probe'))
# 逐动作证据的生命周期阶段，顺序即证据累积顺序。
STAGES = ('requested', 'gateway_received', 'executed', 'acknowledged')

# command 到具体函数的分发表，供 audit_run 包装的 run() 统一进入证据回放。
_DISPATCH = {
    'ingest_page': lambda db, x: ingest_page(db, x.pop('page_id'), x),
    'record_action': lambda db, x: record_action(db, x),
    'reclassify_action': lambda db, x: reclassify_action(
        db, x['request_id'], x['kind'], x.get('reason', '')),
    'reconcile': lambda db, x: reconcile(db, x['id'], x['claim'], x['period']),
    'issue_bill': lambda db, x: issue_bill(db, x),
    'apply_payment': lambda db, x: apply_payment(db, x['bill'], x['amount']),
    'correct_bill': lambda db, x: correct_bill(db, x),
}


def ensure(db):
    """创建本模块所需表。所有表只追加或受控状态流转，不回写已接收原件。"""
    db.execute(
        'CREATE TABLE IF NOT EXISTS gw_pages('
        'id TEXT PRIMARY KEY, claim_id TEXT, period INTEGER, gateway_id TEXT,'
        'generation INTEGER, window_start INTEGER, window_end INTEGER,'
        'raw_digest TEXT NOT NULL, raw_bytes TEXT, reads INTEGER, writes INTEGER,'
        'state TEXT)')
    db.execute(
        'CREATE TABLE IF NOT EXISTS gw_page_lines('
        'page_id TEXT, line_no INTEGER, op TEXT, total INTEGER, corrupted INTEGER,'
        'PRIMARY KEY(page_id,line_no))')
    db.execute(
        'CREATE TABLE IF NOT EXISTS action_evidence('
        'request_id TEXT PRIMARY KEY, claim_id TEXT, period INTEGER, op TEXT,'
        'kind TEXT, gateway_id TEXT, page_id TEXT, stages TEXT,'
        'receipt_count INTEGER)')
    # 一个请求身份可能在多个网关页上被计数（故障切换重叠），用关联表逐页留痕。
    db.execute(
        'CREATE TABLE IF NOT EXISTS action_page_links('
        'request_id TEXT, page_id TEXT, PRIMARY KEY(request_id,page_id))')
    db.execute(
        'CREATE TABLE IF NOT EXISTS reconciliations('
        'id TEXT PRIMARY KEY, claim_id TEXT, period INTEGER, op TEXT,'
        'lower_bound INTEGER, upper_bound INTEGER, proven_ids INTEGER,'
        'pages_used TEXT, bounds_state TEXT)')
    db.execute(
        'CREATE TABLE IF NOT EXISTS bills('
        'id TEXT PRIMARY KEY, claim_id TEXT, period INTEGER, mode TEXT,'
        'read_rate INTEGER, write_rate INTEGER,'
        'confirmed_amount INTEGER, disputed_amount INTEGER, discount_amount INTEGER,'
        'paid_amount INTEGER, balance_due INTEGER, state TEXT,'
        'reconciliation_id TEXT)')
    db.execute(
        'CREATE TABLE IF NOT EXISTS bill_lines('
        'bill_id TEXT, line_no INTEGER, kind TEXT, op TEXT,'
        'units INTEGER, amount INTEGER, evidence_ref TEXT,'
        'PRIMARY KEY(bill_id,line_no))')
    db.execute(
        'CREATE TABLE IF NOT EXISTS bill_corrections('
        'id TEXT PRIMARY KEY, bill_id TEXT, kind TEXT, op TEXT,'
        'units INTEGER, amount INTEGER, evidence_ref TEXT, reason TEXT,'
        'balance_after INTEGER, state TEXT)')


def _digest(raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def ingest_page(db, page_id, payload):
    """接收一个网关用量页原件并冻结。

    必需字段：claim、period、gateway、generation、window=[start,end]、
    reads、writes，以及原始字节 raw（字符串或字节）。原始字节摘要、采集窗口
    和网关代次一经接收不可改写；同 id 重放保持幂等，任何字段冲突都拒绝。
    可在 corrupted_ops 中声明某类动作的原件损坏，损坏总数退出对账但页保留。
    """
    with transaction(db):
        ensure(db)
        required = ('claim', 'period', 'gateway', 'generation', 'window',
                    'reads', 'writes', 'raw')
        if not isinstance(payload, dict) or any(k not in payload for k in required):
            return {'decision': 'invalid_page'}
        window = payload['window']
        if (not isinstance(window, (list, tuple)) or len(window) != 2
                or not all(isinstance(v, int) for v in window)
                or window[0] > window[1]
                or min(payload['period'], payload['generation'],
                       payload['reads'], payload['writes']) < 0):
            return {'decision': 'invalid_page'}
        corrupted = tuple(payload.get('corrupted_ops', ()))
        if any(op not in OPS for op in corrupted):
            return {'decision': 'invalid_page'}
        raw_digest = _digest(payload['raw'])
        old = db.execute('SELECT * FROM gw_pages WHERE id=?', (page_id,)).fetchone()
        frozen = (payload['claim'], payload['period'], payload['gateway'],
                  payload['generation'], window[0], window[1])
        if old:
            same = (old['claim_id'], old['period'], old['gateway_id'],
                    old['generation'], old['window_start'], old['window_end'])
            if old['raw_digest'] != raw_digest or same != frozen:
                return {'decision': 'blocked', 'reason': 'immutable_page_conflict'}
            return {'decision': 'reused', 'state': old['state']}
        db.execute(
            'INSERT INTO gw_pages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (page_id, payload['claim'], payload['period'], payload['gateway'],
             payload['generation'], window[0], window[1], raw_digest,
             payload['raw'] if isinstance(payload['raw'], str)
             else payload['raw'].decode('utf-8', 'replace'),
             payload['reads'], payload['writes'], 'received'))
        line_no = 0
        for op, total in (('read', payload['reads']), ('write', payload['writes'])):
            line_no += 1
            db.execute('INSERT INTO gw_page_lines VALUES(?,?,?,?,?)',
                       (page_id, line_no, op, total, int(op in corrupted)))
        record(db, 'billing', page_id, 'ingest_page', payload['generation'],
               {'payload': {k: v for k, v in payload.items() if k != 'raw'},
                'raw_digest': raw_digest, 'corrupted_ops': corrupted})
        return {'decision': 'received', 'raw_digest': raw_digest}


def record_action(db, payload):
    """登记一个逐动作证据事件。

    以客户请求身份 request_id 为主键：同一请求的重试、多次成功回执只累积到
    同一行，绝不新增客户请求。kind 为 replica_sync/retry/recovery_probe 时
    标记为内部动作，永不进入可收费计数。stage 在四阶段内单向推进，重复或
    乱序回执幂等合并。
    """
    with transaction(db):
        ensure(db)
        required = ('request_id', 'claim', 'period', 'op', 'kind', 'stage')
        if not isinstance(payload, dict) or any(k not in payload for k in required):
            return {'decision': 'invalid_action'}
        if payload['op'] not in OPS or payload['stage'] not in STAGES \
                or payload['period'] < 0:
            return {'decision': 'invalid_action'}
        internal = payload['kind'] in INTERNAL_KINDS
        if payload.get('page'):
            page = db.execute(
                'SELECT claim_id, period FROM gw_pages WHERE id=?',
                (payload['page'],)).fetchone()
            if not page or page['claim_id'] != payload['claim'] \
                    or page['period'] != payload['period']:
                return {'decision': 'blocked', 'reason': 'page_identity_conflict'}
        row = db.execute('SELECT * FROM action_evidence WHERE request_id=?',
                         (payload['request_id'],)).fetchone()
        if row:
            if row['claim_id'] != payload['claim'] or row['op'] != payload['op']:
                return {'decision': 'blocked', 'reason': 'request_identity_conflict'}
            # 跨账期重试沿用请求原件的账期：重试不是新账期里的新客户请求。
            cross_period = row['period'] != payload['period']
            if cross_period and payload['kind'] != 'retry':
                return {'decision': 'blocked', 'reason': 'request_identity_conflict'}
            stages = set(json.loads(row['stages']))
            before = len(stages)
            stages.add(payload['stage'])
            receipts = row['receipt_count'] + (1 if payload['stage'] == 'acknowledged' else 0)
            db.execute('UPDATE action_evidence SET stages=?, receipt_count=? WHERE request_id=?',
                       (json.dumps(sorted(stages)), receipts, payload['request_id']))
            if payload.get('page'):
                db.execute(
                    'INSERT OR IGNORE INTO action_page_links VALUES(?,?)',
                    (payload['request_id'], payload['page']))
            record(db, 'billing', payload['request_id'], 'action_stage', len(stages),
                   {'payload': payload, 'merged': True,
                    'new_stage': len(stages) != before, 'internal': internal,
                    'cross_period_retry': cross_period})
            return {'decision': 'merged', 'stages': sorted(stages),
                    'receipt_count': receipts, 'internal': internal,
                    'period': row['period'], 'cross_period_retry': cross_period}
        stages = [payload['stage']]
        receipts = 1 if payload['stage'] == 'acknowledged' else 0
        db.execute('INSERT INTO action_evidence VALUES(?,?,?,?,?,?,?,?,?)',
                   (payload['request_id'], payload['claim'], payload['period'],
                    payload['op'], payload['kind'], payload.get('gateway'),
                    payload.get('page'), json.dumps(stages), receipts))
        if payload.get('page'):
            db.execute('INSERT OR IGNORE INTO action_page_links VALUES(?,?)',
                       (payload['request_id'], payload['page']))
        record(db, 'billing', payload['request_id'], 'action_stage', 1,
               {'payload': payload, 'merged': False, 'internal': internal})
        return {'decision': 'recorded', 'stages': stages,
                'receipt_count': receipts, 'internal': internal}


def reclassify_action(db, request_id, kind, reason):
    """原件恢复后修正一个请求身份的性质（客户动作 ↔ 内部动作）。

    只改性质判定，不改请求身份、账期和已封存的页；修正本身进证据台账，
    下次 reconcile 据此重算上下界。
    """
    with transaction(db):
        ensure(db)
        row = db.execute('SELECT * FROM action_evidence WHERE request_id=?',
                         (request_id,)).fetchone()
        if not row:
            return {'decision': 'blocked', 'reason': 'unknown_request'}
        if kind not in ('customer', *tuple(INTERNAL_KINDS)):
            return {'decision': 'invalid_action'}
        before = row['kind']
        db.execute('UPDATE action_evidence SET kind=? WHERE request_id=?',
                   (kind, request_id))
        record(db, 'billing', request_id, 'reclassify', 1,
               {'from': before, 'to': kind, 'reason': reason})
        return {'decision': 'reclassified', 'request_id': request_id,
                'from': before, 'to': kind}


def _page_sets(db, claim_id, period, op):
    """返回该 (卷,账期,动作) 下各网关页的逐动作身份集合与干净总数。"""
    pages = db.execute(
        'SELECT id, gateway_id, generation FROM gw_pages '
        'WHERE claim_id=? AND period=? AND state=? ORDER BY generation,id',
        (claim_id, period, 'received')).fetchall()
    page_totals, page_id_sets, used = [], [], []
    for page in pages:
        line = db.execute(
            'SELECT total, corrupted FROM gw_page_lines WHERE page_id=? AND op=?',
            (page['id'], op)).fetchone()
        if not line or line['corrupted']:
            continue
        page_totals.append(line['total'])
        ids = {r['request_id'] for r in db.execute(
            'SELECT request_id FROM action_page_links WHERE page_id=?',
            (page['id'],))}
        page_id_sets.append(ids)
        used.append(page['id'])
    return page_totals, page_id_sets, used


def _identity_sets(db, claim_id, period, op, page_id_sets):
    """拆出客户类身份、内部动作身份，以及逐页证明的跨页客户身份重叠。"""
    rows = db.execute(
        'SELECT request_id, kind, page_id FROM action_evidence '
        'WHERE claim_id=? AND period=? AND op=?',
        (claim_id, period, op)).fetchall()
    customer, internal = set(), set()
    for row in rows:
        (internal if row['kind'] in INTERNAL_KINDS else customer).add(row['request_id'])
    page_customer = [ids & customer for ids in page_id_sets]
    union_customer = set().union(*page_customer) if page_customer else set()
    overlap = (sum(len(ids) for ids in page_customer) - len(union_customer))
    return customer, internal, overlap


def reconcile(db, recon_id, claim_id, period):
    """对一个卷的一个账期做逐动作对账，输出可证明的读写上下界。

    下界（确定发生过的唯一动作数）= max(各干净页总数, 已证实唯一身份数)；
    上界（在不把同身份重复计数的前提下，可能的唯一动作数）= 各干净页总数之
    和，扣减逐动作原件能证明的跨页同身份重叠。聚合页只给总数、给不出交集时，
    区间保持开放，绝不编造一组唯一请求数。
    """
    with transaction(db):
        ensure(db)
        if not db.execute('SELECT 1 FROM claims WHERE id=?', (claim_id,)).fetchone():
            return {'decision': 'blocked', 'reason': 'unknown_claim'}
        prefix = recon_id + ':'
        existing = db.execute(
            'SELECT DISTINCT claim_id, period FROM reconciliations '
            'WHERE substr(id,1,?)=?', (len(prefix), prefix)).fetchone()
        if existing and (existing['claim_id'], existing['period']) != (claim_id, period):
            return {'decision': 'blocked', 'reason': 'reconciliation_identity_conflict'}
        result = {'decision': 'reconciled', 'claim': claim_id, 'period': period,
                  'ops': {}}
        stored = []
        for op in OPS:
            page_totals, page_id_sets, used = _page_sets(db, claim_id, period, op)
            customer, internal, overlap = _identity_sets(
                db, claim_id, period, op, page_id_sets)
            proven_count = len(customer)
            # 上界：各干净页总数之和，扣减逐动作原件能证明的跨页同身份重叠。
            # 页摘要的异同不能推断交集；没有原件的匿名页位之间不做扣减。
            upper = sum(page_totals) - overlap
            # 下界：默认取最大单页总数；若逐动作原件证明页位里含内部动作，
            # 这些页位不是客户请求，按证据把该页可收费位下调。
            evidence_floor = 0
            for total, ids in zip(page_totals, page_id_sets):
                cust, intern = len(ids & customer), len(ids & internal)
                anonymous = max(total - cust - intern, 0)
                evidence_floor = max(evidence_floor, cust + anonymous)
            lower = max(proven_count, evidence_floor) if page_id_sets else proven_count
            upper = max(upper, lower)
            corrupted = [r['page_id'] for r in db.execute(
                'SELECT DISTINCT l.page_id FROM gw_page_lines l '
                'JOIN gw_pages p ON p.id=l.page_id '
                'WHERE l.op=? AND l.corrupted=1 AND p.claim_id=? AND p.period=?',
                (op, claim_id, period)).fetchall()]
            # 所有页位都有逐动作客户身份且无损坏、无匿名位时，边界才是精确值。
            fully_identified = page_id_sets and all(
                total <= len(ids) for total, ids in zip(page_totals, page_id_sets))
            if lower == upper and fully_identified and not corrupted:
                bounds_state = 'exact'
            else:
                bounds_state = 'provisional_bounds'
            row_id = recon_id + ':' + op
            db.execute(
                'INSERT INTO reconciliations VALUES(?,?,?,?,?,?,?,?,?) '
                'ON CONFLICT(id) DO UPDATE SET lower_bound=excluded.lower_bound,'
                'upper_bound=excluded.upper_bound, proven_ids=excluded.proven_ids,'
                'pages_used=excluded.pages_used, bounds_state=excluded.bounds_state',
                (row_id, claim_id, period, op, lower, upper, proven_count,
                 json.dumps(used), bounds_state))
            stored.append(row_id)
            result['ops'][op] = {'lower_bound': lower, 'upper_bound': upper,
                                 'proven_ids': proven_count,
                                 'pages': used, 'corrupted_pages': corrupted,
                                 'bounds_state': bounds_state}
        record(db, 'billing', recon_id, 'reconcile', 1,
               {'claim': claim_id, 'period': period, 'result': result['ops']})
        result['reconciliation_ids'] = stored
        return result


def _bounds(db, recon_id, op):
    row = db.execute('SELECT * FROM reconciliations WHERE id=? AND op=?',
                     (recon_id + ':' + op, op)).fetchone()
    if not row:
        return None
    return row['lower_bound'], row['upper_bound'], row['bounds_state']


def issue_bill(db, payload):
    """按合同允许的两种进程出具账单。

    mode='hold'：本账期只发待核对用量说明，不收有争议费用，应付款为 0；
    mode='capped'：就已证实的最小用量开封顶暂收账单，只收下界，余量保留为
    争议额度，待逐动作原件到齐后补收或冲正。确定收费、争议保留、优惠、已付
    款分行记录；同一账单 id 重放幂等。
    """
    with transaction(db):
        ensure(db)
        required = ('id', 'claim', 'period', 'mode', 'read_rate', 'write_rate')
        if not isinstance(payload, dict) or any(k not in payload for k in required):
            return {'decision': 'invalid_bill'}
        if payload['mode'] not in ('hold', 'capped') \
                or min(payload['read_rate'], payload['write_rate']) < 0:
            return {'decision': 'invalid_bill'}
        old = db.execute('SELECT * FROM bills WHERE id=?', (payload['id'],)).fetchone()
        if old:
            return {'decision': 'reused', 'state': old['state'],
                    'balance_due': old['balance_due']}
        recon_id = payload.get('reconciliation') or ('recon:' + payload['claim']
                                                     + ':' + str(payload['period']))
        bounds = {op: _bounds(db, recon_id, op) for op in OPS}
        if any(v is None for v in bounds.values()):
            return {'decision': 'blocked', 'reason': 'reconciliation_missing'}
        rates = {'read': payload['read_rate'], 'write': payload['write_rate']}
        confirmed_units, disputed_units = {}, {}
        for op in OPS:
            lower, upper, _state = bounds[op]
            confirmed_units[op] = lower if payload['mode'] == 'capped' else 0
            disputed_units[op] = upper - confirmed_units[op]
        confirmed = sum(confirmed_units[op] * rates[op] for op in OPS)
        disputed = sum(disputed_units[op] * rates[op] for op in OPS)
        discount = max(0, int(payload.get('discount', 0)))
        if discount > confirmed:
            return {'decision': 'blocked', 'reason': 'discount_exceeds_confirmed'}
        balance = confirmed - discount
        state = 'payable' if balance > 0 else ('settled' if confirmed > 0
                                               else 'under_review')
        db.execute('INSERT INTO bills VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (payload['id'], payload['claim'], payload['period'],
                    payload['mode'], rates['read'], rates['write'],
                    confirmed, disputed, discount, 0, balance, state, recon_id))
        line_no = 0
        for op in OPS:
            if confirmed_units[op]:
                line_no += 1
                db.execute('INSERT INTO bill_lines VALUES(?,?,?,?,?,?,?)',
                           (payload['id'], line_no, 'confirmed', op,
                            confirmed_units[op], confirmed_units[op] * rates[op],
                            recon_id + ':' + op))
            if disputed_units[op]:
                line_no += 1
                db.execute('INSERT INTO bill_lines VALUES(?,?,?,?,?,?,?)',
                           (payload['id'], line_no, 'disputed_hold', op,
                            disputed_units[op], disputed_units[op] * rates[op],
                            recon_id + ':' + op))
        if discount:
            line_no += 1
            db.execute('INSERT INTO bill_lines VALUES(?,?,?,?,?,?,?)',
                       (payload['id'], line_no, 'discount', 'both', discount,
                        -discount, payload.get('discount_ref', 'contract')))
        record(db, 'billing', payload['id'], 'issue_bill', 1,
               {'payload': {k: v for k, v in payload.items()},
                'confirmed_units': confirmed_units,
                'disputed_units': disputed_units, 'state': state})
        return {'decision': 'issued', 'bill': payload['id'], 'mode': payload['mode'],
                'state': state, 'confirmed_amount': confirmed,
                'disputed_amount': disputed, 'discount_amount': discount,
                'balance_due': balance}


def apply_payment(db, bill_id, amount):
    """登记客户付款。付款只冲抵已确认的应付款，争议保留款不可被索取。"""
    with transaction(db):
        ensure(db)
        if not isinstance(amount, int) or amount < 0:
            return {'decision': 'invalid_payment'}
        bill = db.execute('SELECT * FROM bills WHERE id=?', (bill_id,)).fetchone()
        if not bill:
            return {'decision': 'blocked', 'reason': 'unknown_bill'}
        unpaid = bill['balance_due'] - bill['paid_amount']
        if amount > unpaid:
            return {'decision': 'blocked', 'reason': 'payment_exceeds_balance'}
        paid = bill['paid_amount'] + amount
        new_state = 'settled' if paid >= bill['balance_due'] else 'partly_paid'
        db.execute('UPDATE bills SET paid_amount=?, state=? WHERE id=?',
                   (paid, new_state, bill_id))
        record(db, 'billing', bill_id, 'payment', 1,
               {'amount': amount, 'paid_total': paid, 'state': new_state})
        return {'decision': 'paid', 'bill': bill_id, 'amount': amount,
                'paid_total': paid, 'balance_due': bill['balance_due'],
                'state': new_state}


def correct_bill(db, payload):
    """对已发账单出具关联原凭证的补收或冲正。

    更正必须引用逐动作原件（reconciliation 行、请求身份或网关页），不允许
    无凭证调账。补收只能落在已证实的新唯一动作上，冲正只能撤回已收过的量；
    更正后的账单总量始终处于对账上下界内，重复入账不会让客户多付。
    """
    with transaction(db):
        ensure(db)
        required = ('id', 'bill', 'kind', 'op', 'units', 'evidence_ref')
        if not isinstance(payload, dict) or any(k not in payload for k in required):
            return {'decision': 'invalid_correction'}
        if payload['kind'] not in ('supplemental', 'reversal') \
                or payload['op'] not in OPS or payload['units'] <= 0:
            return {'decision': 'invalid_correction'}
        if db.execute('SELECT 1 FROM bill_corrections WHERE id=?',
                      (payload['id'],)).fetchone():
            row = db.execute('SELECT * FROM bill_corrections WHERE id=?',
                             (payload['id'],)).fetchone()
            return {'decision': 'reused', 'state': row['state'],
                    'balance_after': row['balance_after']}
        bill = db.execute('SELECT * FROM bills WHERE id=?', (payload['bill'],)).fetchone()
        if not bill:
            return {'decision': 'blocked', 'reason': 'unknown_bill'}
        ref = payload['evidence_ref']
        known = {r[0] for r in db.execute(
            "SELECT id FROM reconciliations UNION ALL SELECT request_id FROM "
            "action_evidence UNION ALL SELECT id FROM gw_pages")}
        if ref not in known:
            return {'decision': 'blocked', 'reason': 'unknown_evidence_ref'}
        rate = bill['read_rate'] if payload['op'] == 'read' else bill['write_rate']
        amount = payload['units'] * rate
        sign = 1 if payload['kind'] == 'supplemental' else -1
        # 该 op 已确认（已向客户收取）的总量，以及对账给出的上下界。
        billed = db.execute(
            "SELECT COALESCE(SUM(units),0) FROM bill_lines WHERE bill_id=? AND op=? "
            "AND kind='confirmed'", (payload['bill'], payload['op'])).fetchone()[0]
        corrected = db.execute(
            "SELECT COALESCE(SUM(CASE WHEN kind='supplemental' THEN units "
            "WHEN kind='reversal' THEN -units ELSE 0 END),0) "
            "FROM bill_corrections WHERE bill_id=? AND op=?",
            (payload['bill'], payload['op'])).fetchone()[0]
        current = billed + corrected
        bound = _bounds(db, bill['reconciliation_id'], payload['op'])
        if not bound:
            return {'decision': 'blocked', 'reason': 'reconciliation_missing'}
        lower, upper, _state = bound
        after = current + sign * payload['units']
        if after < lower or after > upper or after < 0:
            return {'decision': 'blocked', 'reason': 'correction_outside_bounds'}
        new_balance = max(0, bill['balance_due'] + sign * amount)
        overpaid = max(0, bill['paid_amount'] - new_balance)
        new_state = 'corrected'
        if payload['kind'] == 'supplemental' and new_balance > bill['paid_amount']:
            new_state = 'payable'
        elif new_balance == 0 and bill['paid_amount'] >= bill['balance_due']:
            new_state = 'settled'
        db.execute('UPDATE bills SET balance_due=?, state=? WHERE id=?',
                   (new_balance, new_state, payload['bill']))
        db.execute('INSERT INTO bill_corrections VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (payload['id'], payload['bill'], payload['kind'],
                    payload['op'], payload['units'], sign * amount, ref,
                    payload.get('reason', ''), new_balance, new_state))
        record(db, 'billing', payload['id'], 'correction', 1,
               {'payload': payload, 'amount': sign * amount,
                'balance_after': new_balance, 'customer_credit': overpaid,
                'state': new_state})
        return {'decision': 'posted', 'correction': payload['id'],
                'kind': payload['kind'], 'amount': sign * amount,
                'units_after': after, 'balance_due': new_balance,
                'customer_credit': overpaid, 'state': new_state}


def settlement_report(db, claim_id, period):
    """给财务的当期结论：此刻确实应付多少、多少读写仍待证。"""
    with transaction(db):
        ensure(db)
        recon_rows = db.execute(
            'SELECT * FROM reconciliations WHERE claim_id=? AND period=? ORDER BY op',
            (claim_id, period)).fetchall()
        pending = {op: None for op in OPS}
        for row in recon_rows:
            pending[row['op']] = row['upper_bound'] - row['lower_bound']
        bills = [dict(r) for r in db.execute(
            'SELECT * FROM bills WHERE claim_id=? AND period=? ORDER BY id',
            (claim_id, period)).fetchall()]
        payable_now = sum(max(0, b['balance_due'] - b['paid_amount']) for b in bills)
        corrections = [dict(r) for r in db.execute(
            'SELECT c.* FROM bill_corrections c JOIN bills b ON b.id=c.bill_id '
            'WHERE b.claim_id=? AND b.period=? ORDER BY c.id',
            (claim_id, period)).fetchall()]
        internal = db.execute(
            'SELECT COUNT(*) FROM action_evidence WHERE claim_id=? AND period=? '
            'AND kind IN (?,?,?)',
            (claim_id, period, *tuple(INTERNAL_KINDS))).fetchone()[0]
        return {
            'claim': claim_id, 'period': period,
            'pending_units': pending,
            'payable_now': payable_now,
            'bills': [{'id': b['id'], 'mode': b['mode'], 'state': b['state'],
                       'confirmed_amount': b['confirmed_amount'],
                       'disputed_amount': b['disputed_amount'],
                       'discount_amount': b['discount_amount'],
                       'paid_amount': b['paid_amount'],
                       'balance_due': b['balance_due']} for b in bills],
            'corrections': [{'id': c['id'], 'bill': c['bill_id'],
                             'kind': c['kind'], 'op': c['op'],
                             'units': c['units'], 'amount': c['amount'],
                             'evidence_ref': c['evidence_ref'],
                             'state': c['state']} for c in corrections],
            'internal_actions_excluded': internal,
        }


@audit_run('billing')
def run(db, x):
    """统一入口：按 op 分发，并由 audit_run 记录可回放的 decision 证据。

    与 pool/claim/recovery 一致，输入输出完整进 evidence 台账，replay 可从
    原始事件逐表重建本模块全部状态。分发选择器叫 command，避免与读写动作的
    op 字段撞名。
    """
    handler = _DISPATCH.get(x.get('command'))
    if handler is None:
        raise ValueError(x.get('command'))
    return handler(db, dict(x))
