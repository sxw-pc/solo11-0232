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
- `cloudlab/__main__.py`：JSON fixture CLI、演示和证据报告。
- `tests/test_workflows.py`：正常、失败、跨系统状态和证据回放测试，运行时打印 `cloudlab.__file__`。

## 数据和恢复约束

1. 落位计划需要两处不同机架且不超出池容量；预留必须兑现为已提交容量，卷声明才可绑定。不同卷的计划可以使用同一机架，但同一计划不能重复使用。
2. 单写卷已有有效绑定时第二工作负载不能取得写权；解绑释放该承诺后，新的绑定和授权才能成立。池缩容或降级会改变既有绑定的风险结论。
3. 恢复要同时满足候选副本地域、已提交预留、完整快照父链、最新围栏和恢复计划。成功提升会围栏旧主、转移绑定预留、撤销旧写者授权；失败与重试都可由 `evidence` 重放验证。

这三个入口的业务结果分别可观察；只有持久化证据和相关实体的版本、身份一致，才能继续改变下游结论。
