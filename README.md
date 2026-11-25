# 卷域供给与恢复台

基础设施 / 云原生离线业务系统。三个入口各自维护不同的业务对象、状态和持久化实体，不需要 Kubernetes 集群、云凭据或外部服务。Python 标准库和 SQLite 即可运行。

## 业务边界

- **池域台账**：存储池容量和故障域。判定某存储池能否承诺独立故障域中的卷副本；状态为reserve 到 committed，过期预留转 expired。持久化实体：pool_capacity、pool_reservation。池故障域变化会使已绑定卷进入风险态
- **卷声明绑定**：卷声明与工作负载绑定。判定声明能否在拓扑与访问模式下取得稳定卷身份；状态为pending 到 bound，冲突时 blocked。持久化实体：volume_claim、volume_binding。绑定结果决定副本恢复是否允许切换主卷
- **副本恢复**：卷副本与恢复快照。决定故障后采用哪个可用副本恢复写入权；状态为healthy 到 suspect 到 fenced 或 promoted。持久化实体：volume_replica、recovery_attempt。恢复主副本改变池预留和绑定可用性

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

1. 同一机架尚有两块空盘但不满足两故障域副本时，池拒绝承诺；换成独立机架后才允许声明绑定。 两个子系统的持久化结论相互改变。同一机架尚有两块空盘但不满足两故障域副本时，池拒绝承诺；换成独立机架后才允许声明绑定。 失败或迟到事实保留可重算的阻断证据
2. 单写卷的旧工作负载解绑未提交，新工作负载同时申请绑定时拒绝；旧绑定事务完成后再试通过。 两个子系统的持久化结论相互改变。单写卷的旧工作负载解绑未提交，新工作负载同时申请绑定时拒绝；旧绑定事务完成后再试通过。 失败或迟到事实保留可重算的阻断证据
3. 主副本失联且增量快照链完整时先围栏再提升；缺少父快照时恢复保持阻断，旧主迟到上报不能夺回写权。 两个子系统的持久化结论相互改变。主副本失联且增量快照链完整时先围栏再提升；缺少父快照时恢复保持阻断，旧主迟到上报不能夺回写权。 失败或迟到事实保留可重算的阻断证据

这三个入口的业务结果分别可观察；只有持久化证据和相关实体的版本、身份一致，才能继续改变下游结论。
