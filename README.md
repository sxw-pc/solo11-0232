# 卷域供给与恢复台

基础设施 / 云原生离线业务系统。三个入口各自维护不同的业务对象、状态和持久化实体，不需要 Kubernetes 集群、云凭据或外部服务。Python 标准库和 SQLite 即可运行。

## 业务边界

- **池域台账**：`pools`、`placement_plans`、`placement_members` 和 `reservations` 保存容量、故障域落位、预留及提交。未兑现的落位计划也占承诺额度。池降级或缩容会把相关预留和绑定标成风险态。
- **卷声明绑定**：`claims`、`bindings`、`writer_grants` 和 `attachments` 保存卷规格、单写者占用、授权及节点挂载。绑定核对预留容量和地域，挂载还要核对写者授权及绑定拓扑。
- **副本恢复**：`replicas`、`snapshots`、`fences`、`restore_plans` 和 `recovery_attempts` 保存副本代次、完整快照父链、围栏、候选计划和提升尝试。提升同时更换绑定的预留并撤销旧写者授权。

所有命令用 SQLite 的 IMMEDIATE 事务提交状态，并保存输入、输出、版本和顺序证据。拒绝也进入 evidence 台账；重复或迟到事件不能默默改写已经成立的承诺。业务表与台账可用 replay 命令从原始事件重建并逐表核对。

## 快速运行

在仓库根目录执行：

```sh
python -m cloudlab demo --db demo.sqlite
python -m cloudlab report --db demo.sqlite
python -m cloudlab replay --db demo.sqlite
python -m unittest discover -s tests -v
```

单独执行一个子系统的 fixture：

```sh
python -m cloudlab pool --db isolated.sqlite --fixture fixtures/pool_ok.json
python -m cloudlab pool --db isolated.sqlite --fixture fixtures/pool_fail.json
```

每个入口提供 *_ok.json 和 *_fail.json。若步骤需要上游承诺，先在同一个数据库依次执行前置入口；demo 展示三者的完整顺序。CLI 返回 decision 和具体阻断 reason。重新演示时使用新的数据库文件，避免幂等键与旧实验相撞。

## 代码导航

- `cloudlab/store.py`：SQLite 初始化、事务、原始输入与决策证据、回放逐表核验。
- `cloudlab/pool.py`：存储池容量和故障域 的业务状态机和独立命令。
- `cloudlab/claim.py`：卷声明与工作负载绑定 的业务状态机和独立命令。
- `cloudlab/recovery.py`：卷副本与恢复快照 的业务状态机和独立命令。
- `cloudlab/key_wrap.py` / `key_service.py` / `decrypt_probe.py`：密钥封装台账、站点轮换回执与单次解密探针（彼此独立的原始证据）。
- `cloudlab/key_rotation.py`：跨站点密钥轮换与逐份快照可读性验收，接入上述三类原件和恢复快照链/恢复计划。
- `cloudlab/__main__.py`：JSON fixture CLI、演示和证据报告。
- `tests/test_workflows.py`：正常、失败、跨系统状态和证据回放测试，运行时打印 `cloudlab.__file__`。

## 数据和恢复约束

1. 落位计划需要两处不同机架且不超出池容量；预留必须兑现为已提交容量，卷声明才可绑定。不同卷的计划可以使用同一机架，但同一计划不能重复使用。
2. 单写卷已有有效绑定时第二工作负载不能取得写权；解绑释放该承诺后，新的绑定和授权才能成立。池缩容或降级会改变既有绑定的风险结论。
3. 恢复要同时满足候选副本地域、已提交预留、完整快照父链、最新围栏和恢复计划。成功提升会围栏旧主、转移绑定预留、撤销旧写者授权；失败与重试都可由 `evidence` 重放验证。

## 密钥轮换与可读性验收

`key_rotation.run(db, payload)` 在既有父链/代次判断之上再加一层“密文是否真的还能打开”的验收，规则如下：

- 轮换范围（`op='rotate'` 的 `scope`）从在线卷延伸到封装台账中的每份快照（含父快照）、显式离线副本和外部封装位置；缺封装的快照以 `missing_wrap` 缺口列出。
- 密钥服务的成功回执只记录站点上报，不能替代逐份快照读回；`recovery_report` / `op='report'` 输出 `certified | restricted | quarantined | revocation_failed | incomplete`，并列出 `quarantined` 快照与每份快照的解密路径。
- 同一 `failed` 探针必须凭追加证据分类为 `missing_key`、`wrap_version_mismatch`（另有 `wrap_invalid`）或 `ciphertext_corrupt`；证据不足时为 `undetermined`，不能仅凭布尔失败认定密文损坏。
- 旧密钥进入 `retiring`，其用途、持有者和 `deadline/hard_deadline` 受限；`renew` 不得越过硬截止，确认泄露（`confirm_compromise`）后一律不得再以“读服务需要”续期。
- 旧密钥只有在所有仍承诺恢复（未隔离）的快照都有真实读回路径、外部副本均已 attest 时才可 `revoke`；`revocation_readiness(db,key)` 给出阻断清单。隔离（`quarantine`）把快照移出承诺集合，因此可按限定时间表撤 K，但隔离期间客户不能用该快照恢复。
- 合同两条路径：路径 A 隔离 S2 → 外部副本处置 → 撤 K → 迟到的独立离线封装 + 密文读回 → 转封 K2 + 客户读回 → `release`；路径 B 用已核验封闭托管环境（`register_escrow`/`escrow_contact`/`open_escrow`）开仅对单快照、短窗口的案，接触证明（`escrow_access`）与最终销毁证明（`destroy` 的 `proof`）必须分别出具。托管方失联则路径 B 阻断并回落到隔离。
- 报告只追加版本（`report_history`/`get_report`），探针、评估、状态事件和密钥接触记录均 append-only；复用旧探针 id 把失败改写成成功会得到 `conflict`，`incident_history` 始终保留客户实际遇到的失败。
- 轮换按 id 幂等重试；基于旧 from-key 的竞争轮换得到 `stale_key_epoch`，部分唯一索引保证每个 claim 至多一把 `current` 密钥；乱序回执标记 `stale` 但不回滚当前版本。
- `recovery.run` 的 `plan_restore` 在传入 `require_readback/check_readability/key_acceptance` 时会额外调用 `key_rotation.gate_restore`；默认行为不变。

```sh
python -B -m unittest discover -s tests -q
```

这三个入口的业务结果分别可观察；只有持久化证据和相关实体的版本、身份一致，才能继续改变下游结论。
