# 检测规则模型、窗口语义与告警状态流转

本文说明三件事：①检测规则如何建模；②乱序/迟到/重复下窗口如何判定；③告警如何去重、合并与流转。
所有机制均为本地内存实现，结论可复现、可解释。

---

## 1. 事件接入与归一化

### 1.1 归一化事件模型 `NormalizedEvent`

| 字段 | 含义 |
|------|------|
| eventId | 稳定 ID：`来源:来源记录ID`，无记录 ID 时为 `来源:报文SHA1`，可从输入复现 |
| source / sourceRecordId | 来源 / 来源侧记录 ID |
| eventType | 归一化事件类型（白名单校验） |
| sourceIp / targetIp / user | 主体/客体（sourceIp 与 user 至少有一个） |
| eventTime | 事件时间（解析多格式：ISO-8601、`yyyy-MM-dd HH:mm:ss`、epochMillis） |
| ingestTime | 本地接入时间 |
| attributes | 其余属性（规则可按属性精确匹配） |

### 1.2 处理顺序与拒绝原因（不静默丢弃）

每条记录必经：**来源路由 → 报文解析 → 时间戳解析 → 业务校验 → 去重**，
失败即落 `RejectedRecord{类别, 原因码, 明细, 时间}`，最终保证 `接受数 + 拒绝数 = 输入数`。

- **PARSE（解析失败，报文层面问题）**

  | 码 | 原因 |
  |----|------|
  | P001 | 原始报文为空 |
  | P002 | 不支持的报文格式或来源 |
  | P003 | JSON 格式非法 |
  | P004 | CSV 格式非法（列数不符等） |
  | P005 | 键值对格式非法 |
  | P006 | 缺少时间戳字段 |
  | P007 | 时间戳格式非法、无法解析 |

- **VALIDATION（业务校验不通过，报文可解析但不合法）**

  | 码 | 原因 |
  |----|------|
  | V001 | 缺少事件来源 |
  | V002 | 缺少事件类型 |
  | V003 | 事件类型不在白名单 |
  | V004 | 主体缺失（sourceIp、user 同时为空） |
  | V005 | 事件时间超出允许的未来偏移（默认 60s） |
  | V006 | 事件时间早于允许的最早时间（默认 3650 天） |
  | V007 | 事件重复到达，已去重 |

> 注意「时间戳」被拆成两类：**缺失/格式非法 = PARSE(P006/P007)**；**能解析但越界 = VALIDATION(V005/V006)**，
> 从而分别定位是「报文坏了」还是「内容不合理」。

---

## 2. 检测规则模型

规则以本地 JSON 描述，顶层 `version` 为规则集版本；规则未单独声明版本时继承规则集版本。

```json
{
  "id": "R-LOGIN-BRUTE-FORCE",
  "type": "FREQUENCY",
  "enabled": true,
  "matchEventType": "LOGIN_FAIL",
  "matchSource": null,
  "matchAttributes": {},
  "threshold": 5,
  "windowSeconds": 60,
  "allowedLatenessSeconds": 30,
  "sequence": [],
  "groupBy": ["user", "sourceIp"],
  "severity": "HIGH",
  "title": "账号 60 秒内登录失败达到 5 次（暴力破解）"
}
```

| 字段 | 说明 |
|------|------|
| type | `THRESHOLD`（阈值计数）/ `FREQUENCY`（频率，阈值语义）/ `SEQUENCE`（时序） |
| matchEventType / matchSource / matchAttributes | 命中条件：类型、来源、属性全等匹配；null/空表示不限定 |
| threshold | 窗口内命中事件数达到该值即触发（THRESHOLD/FREQUENCY） |
| windowSeconds | 事件时间滚动窗口长度 |
| allowedLatenessSeconds | 允许迟到时间，决定 watermark 与窗口何时 finalize |
| sequence | SEQUENCE 规则要求按**事件时间**先后出现的类型序列（非连续） |
| groupBy | 关联分组字段：sourceIp / targetIp / user / source / eventType / 自定义属性 |

### 2.1 三类规则的表达

- **阈值 / 频率**：窗口内同组匹配事件计数 `>= threshold` 触发一次。例如防火墙拦截 ≥3、登录失败 ≥5。
- **时序关系**：窗口内同组事件按事件时间能按顺序覆盖 `sequence` 即触发。
  例如 `LOGIN_SUCCESS → PRIVILEGE_ESCALATION → DATA_EXPORT`；即使接入顺序相反（乱序），
  引擎按事件时间排序后仍能识别（见用例 2.07、4.02）。

### 2.2 窗口与 watermark（乱序、迟到、重复的判定依据）

- **窗口切分**：窗口键 = `规则ID | 窗口起始 | 分组值`，窗口起始 = `floor(eventTime / windowMs)`。
  事件永远归入它**事件时间**所属的窗口，与到达顺序无关，所以结论稳定、可复现。
- **watermark**：对每条规则维护 `watermark = 观测到的最大匹配事件时间 − allowedLateness`。
  - 只有**真正匹配该规则**的事件才推进它的 watermark（无关类型/来源不会误关窗口）。
  - 先对事件求值、再推进 watermark，保证同批次乱序事件不会被「自己人」判迟到。
- **窗口关闭（finalize）**：当 `watermark >= 窗口结束点` 时窗口关闭并登记起始点。
- **乱序**：窗口关闭前到达的更早事件一律计入，证据按 `(eventTime, eventId)` 排序。
- **迟到**：事件所属窗口已关闭 → 标记 late，只登记，**不参与求值、不触发、不复活旧告警**，
  也不会为迟到事件重建空窗口。
- **重复**：窗口内按 `eventId` 去重；窗口 `fired` 标记保证同一窗口最多产出一次。

### 2.3 触发产物 `AlertSeed`

规则命中产出种子：`ruleId/ruleVersion`、`correlationKey`、severity、title、
首事件时间、触发时间、命中事件 ID 列表、evidence（窗口起止、分组、计数、首尾事件等可解释证据）。

---

## 3. 告警去重、合并与状态流转

### 3.1 幂等去重（三层）

1. 接入层 `DedupCache`：`来源 + 来源记录ID`（无 ID 用报文 SHA1）只放行一次，重复 → V007。
2. 窗口层：按 `eventId` 去重，窗口 `fired` 只触发一次。
3. 告警层：`correlationKey = 规则ID|窗口起始|分组值`，落库幂等；告警 ID 由 correlationKey
   经 SHA-256 派生，天然可复现。

因此「同一批数据被重复消费」在任意一层都不会产生第二条告警（用例 1.11 / 2.10 / 3.01 / 4.03 / 4.05）。

### 3.2 事件链合并

- 同 correlationKey 的后续种子不新增告警，只把**新出现的** eventId 并入主告警，
  并在 evidence / 审计里记录「补充了几个事件」或「重复消费命中，告警不变」。
- 显式 `merge(childId, parentId)`：仅允许**同一规则**下合并；
  子告警进入 `MERGED` 终态并记录 `mergedInto`，父告警吸收子链事件并留痕（用例 3.05/3.06）。

### 3.3 合法状态流转

```
                ┌─────────────── ACKNOWLEDGED ───────────────┐
                │                                             │
   NEW ─────────┤                  RESOLVED ──(重开)──► ACKNOWLEDGED
                │                     │
                ▼                     ▼
             MERGED（终态）        MERGED（终态）
```

合法转换表（非法转换抛 `IllegalAlertTransitionException`）：

| 当前状态 | 可流转到 |
|----------|----------|
| NEW | ACKNOWLEDGED、RESOLVED、MERGED |
| ACKNOWLEDGED | RESOLVED、MERGED |
| RESOLVED | ACKNOWLEDGED（重开）、MERGED |
| MERGED | （无，终态） |

每次流转都追加一条 `AlertTransition{时间, from, to, operator, reason}`，全程可追溯（用例 3.03/3.04）。

### 3.4 并发一致性

- `DetectionPipeline` 以批次锁串行化「归一化 → 引擎 → 落库」。
- `AlertService` 以同链锁串行化同 correlationKey 的落库/合并；存储使用并发结构。
- 因此并发接入时：同事件链恰好一条主告警且事件链完整；不同事件链数量精确；
  新告警一律为 NEW（用例 3.08/3.09/4.04/4.05）。

### 3.5 规则调整与历史可复现

- `RuleRepository` 保存当前 `RuleSet` 及所有历史版本快照；每条告警固化 `ruleId@ruleVersion`。
- 规则调整（如阈值 3→4、启用/禁用规则）只影响调整后的新评估；
  历史告警仍带旧版本号，可用历史快照复现当时结论（用例 4.06/4.07）。

---

## 4. 配置项（`application.properties`）

| 配置 | 默认 | 作用 |
|------|------|------|
| threat.rules-resource | rules-default.json | 规则资源（classpath） |
| threat.allowed-event-types | 8 种内置类型 | 事件类型白名单（V003） |
| threat.max-future-skew-seconds | 60 | 允许的未来时间偏移（V005） |
| threat.max-age-days | 3650 | 允许的最大历史跨度（V006） |

## 5. 本地验证

见仓库根目录 `README.md` 第 3 节：`mvn test`（四个业务域 38 例）与 `--demo` 端到端演示。
