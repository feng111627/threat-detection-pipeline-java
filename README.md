# 本地威胁检测与告警关联流水线

纯本地实现的事件接入 → 规则检测 → 告警产出链路，不依赖任何外部服务。
使用本地生成器模拟多来源安全日志，保证在多来源、乱序、重复、并发场景下结果稳定、可解释。

## 链路总览

```
RawRecord(来源+原始行)
   │  IngestionService：解析(PARSE) → 业务校验(VALIDATE) → eventId 幂等去重
   ▼
SecurityEvent(归一化事件)
   │  RuleEngine：按事件时间落入滚动窗口(tumbling)，按 groupBy 关联
   ▼
AlertCandidate(命中，携带规则版本)
   │  AlertStore：按 (ruleId, chainKey) 去重，同链合并
   ▼
Alert(状态机流转，全程审计)
```

## 事件接入与拒绝模型

- 四种来源（`AUTH_LOG` / `FIREWALL` / `HOST_AGENT` / `IDS`）均为 `key=value` 文本行，
  字段名映射按来源配置（`PipelineConfig#eventParsers`），统一归一化为 `SecurityEvent`。
- 任何记录都不会被静默丢弃，接入结果三态：`ACCEPTED` / `REJECTED` / `DUPLICATE`。
- 拒绝记录 `RejectionRecord` 带阶段与原因，两类失败可分别定位：
  - `PARSE`（解析失败）：格式非法、字段缺失、时间戳异常、未知事件类型、不支持的来源；
  - `VALIDATE`（业务校验不通过）：事件ID不合法、时间戳超出未来偏移/保留窗口、主机名为空、
    登录/文件类事件缺少用户字段。
- 幂等：已见过的 `eventId` 重复到达返回 `DUPLICATE`，不重复进入检测链路，
  这是「同一批数据重复消费不重复产出告警」的第一道保障。

## 检测规则模型

`DetectionRule` 字段：

| 字段 | 含义 |
|---|---|
| `ruleId` / `version` | 规则标识与版本；版本升级重置该规则窗口，告警固化命中时版本 |
| `type` | `THRESHOLD` / `FREQUENCY` / `SEQUENCE` |
| `eventTypes` | 参与判定的事件类型集合 |
| `threshold` | 阈值（FREQUENCY：窗口内事件数；THRESHOLD：数值属性下限） |
| `window` | 窗口长度（对齐 epoch 的滚动窗口） |
| `groupBy` | 关联维度：`user` / `host` / 任意属性名，同组构成一条事件链 |
| `valueField` | THRESHOLD 使用的数值属性名（如端口数 `ports`） |
| `sequence` | SEQUENCE 要求按事件时间出现的类型子序列 |

窗口语义（稳定性保证）：

- 窗口按**事件时间**对齐到 epoch，判定只依赖窗口内事件集合，**与到达顺序无关**；
  乱序/迟到事件落入各自窗口独立判定，最终结果与顺序到达一致。
- 窗口内按 `eventId` 去重，重复事件不影响计数。
- 每个 (规则, 关联键, 窗口) 最多命中一次；重复消费被接入层幂等拦截，不会重复产出。
- 规则版本升级后该规则窗口状态重置；同版本重复加载保留状态。
  历史告警保留旧版本号，用对应版本规则重放同一批事件可复现历史结论。

默认规则（`PipelineConfig#defaultRules`）：

| 规则 | 类型 | 含义 |
|---|---|---|
| `R-BRUTE-FORCE` | FREQUENCY | 同一用户 5 分钟内登录失败 ≥ 3 次 |
| `R-PORT-SCAN` | THRESHOLD | 同一主机 1 分钟内单次扫描端口数 ≥ 10 |
| `R-BREACH-PATH` | SEQUENCE | 同一用户 10 分钟内出现 登录失败→登录成功→进程启动 |

## 告警模型与状态流转

- 去重键：`(ruleId, chainKey)`，`chainKey = ruleId|关联键`。
  同一事件链的多次命中（不同窗口）合并进同一条告警：`hitCount` 累计命中次数，
  `eventIds` 累计各次命中的窗口事件，`ruleVersion` 取最新。
- 并发安全：`AlertStore` 使用并发Map + `computeIfAbsent`，`Alert` 变更方法加锁，
  并发接入时告警数量与状态一致。

状态机（`AlertStatus`）：

```
NEW ──► ACKNOWLEDGED ──► RESOLVED
 │           │
 └──► SUPPRESSED ◄──────┘        (RESOLVED / SUPPRESSED 为终态)
```

- 非法流转（跳级、终态回转）抛出 `IllegalStateException`；
- 每次合法流转写入 `StatusChange(from, to, at, reason)` 审计历史，全程可追溯。

## 本地验证方法

```bash
mvn test          # 全部 21 个用例
mvn compile       # 仅编译
```

测试日志会打印覆盖的业务场景与用例通过情况，形如：

```
[业务场景] 多来源接入与归一化 | 用例: 四类解析失败原因可区分定位 => 通过
[业务场景] 窗口关联检测       | 用例: 乱序到达判定结果与顺序一致 => 通过
[业务场景] 并发接入一致性     | 用例: 8线程重复提交同批事件仅产出1条告警 => 通过
```

测试类与业务场景对应关系：

| 测试类 | 覆盖场景 |
|---|---|
| `IngestionServiceTest` | 多来源接入与归一化、解析/校验失败分阶段定位、幂等去重 |
| `RuleEngineTest` | 频率/阈值/时序规则、乱序、迟到、重复事件、窗口驱逐 |
| `ConcurrencyPipelineTest` | 并发接入告警数量一致、同链合并、整批重复消费 |
| `AlertLifecycleTest` | 告警去重合并、状态流转合法性与审计 |
| `RuleAdjustmentTest` | 规则调整后历史结论可复现、版本升级语义 |

本地事件模拟：`LocalEventGenerator` 按种子确定性生成四种来源的日志，
并提供 `shuffled`（乱序）与 `withDuplicates`（重复）样本构造。
