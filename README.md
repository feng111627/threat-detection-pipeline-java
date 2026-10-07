# 本地威胁检测与告警关联流程

一个**只依赖本地能力**（Spring Boot 内存组件 + 本地 JSON 规则 + 本地事件模拟器，不接任何外部服务）
的威胁检测流水线，覆盖「事件接入 → 规则检测/窗口关联 → 告警产出」全链路，并在
**多来源、乱序、迟到、重复、并发、规则调整**等条件下给出稳定且可解释的结果。

## 1. 它能做什么

| 环节 | 能力 |
|------|------|
| 事件接入与归一化 | 多来源（firewall=JSON / edr=CSV / iam=键值对）统一归一化；**解析失败(PARSE) 与业务校验不通过(VALIDATION) 分别给出可定位的原因码**；任何记录都不静默丢弃 |
| 规则检测与窗口关联 | 规则本地 JSON 可配置，支持**阈值(THRESHOLD)、频率(FREQUENCY)、时序(SEQUENCE)**；事件时间滚动窗口 + watermark；乱序、迟到、重复到达判定稳定；重复消费不重复产告警 |
| 告警去重/合并/状态流转 | 按 correlationKey 幂等去重；同事件链自动合并；合法状态机 + 全程审计；并发下数量与状态一致；告警固化规则版本，历史可复现 |

## 2. 模块结构

```
model      归一化事件 / 拒绝原因(类别+码) / 告警 / 状态 / 流转记录
ingest     SourceAdapter(JSON/CSV/KV)、EventNormalizer(解析→校验→去重)、DedupCache
rule       DetectionRule / RuleSet(版本快照) / JsonRuleLoader / RuleRepository
engine     WindowManager(窗口+watermark+求值)、DetectionEngine、AlertSeed
alert      AlertService(幂等/合并/状态机)、AlertStore、IllegalAlertTransitionException
pipeline   DetectionPipeline（端到端编排，批次级并发安全）
simulator  LocalEventSimulator（确定性生成多来源/乱序/迟到/重复/坏数据）
config     Bean 装配、DemoRunner（--demo 本地演示）
```

## 3. 快速开始（本地验证）

> 需要 JDK 21+、Maven 3.6+，全程离线可跑（依赖已在本地仓库）。

### 3.1 运行测试（推荐先看这个）

```bash
mvn test
```

测试日志按「业务域 → 用例编号」打印每条用例的 `[通过]/[失败]`，结尾给出汇总。
共 4 个业务域 38 个业务用例（另有 1 个 Spring 上下文用例）：

- 业务域一：多来源接入与归一化（12 例）
- 业务域二：窗口关联与规则检测（10 例）
- 业务域三：告警去重/合并/状态流转（9 例）
- 业务域四：端到端：并发 / 乱序迟到 / 重复消费 / 规则调整（7 例）

只跑某一域：

```bash
mvn test -Dtest=Domain1IngestNormalizationTest   # 接入域
mvn test -Dtest=Domain2WindowDetectionEngineTest # 引擎域
mvn test -Dtest=Domain3AlertServiceTest          # 告警域
mvn test -Dtest=Domain4PipelineIntegrationTest   # 端到端域
```

### 3.2 本地端到端演示（模拟事件 → 真实跑链路 → 打印结果）

```bash
mvn package -DskipTests
java -jar target/threat-detection-pipeline-java-1.0-SNAPSHOT.jar --demo
```

演示三个场景并对每个场景**再重复消费一遍同一批数据**，可以直观看到：
拒绝原因分类、迟到事件不计入、告警只在首次产出、重复消费零新告警。
（应用是 Web 服务，演示输出完成后可用 Ctrl+C 退出。）

### 3.3 调整规则后验证

- 默认规则：`src/main/resources/rules-default.json`（v1）
- 调整版本：`src/main/resources/rules-v2.json`（v2：上调防火墙阈值 3→4，启用默认关闭的恶意软件规则）

切换方式：改 `application.properties` 的 `threat.rules-resource`，或通过 `RuleRepository.load("rules-v2.json")`。
规则仓库保留历史版本快照，告警上固化触发时的规则版本，历史结论可复现（见用例 4.06 / 4.07）。

## 4. 关键设计结论（便于快速核对）

- **不静默丢弃**：`接受数 + 拒绝数 = 输入数`；每条拒绝带 `类别(PARSE/VALIDATION) + 原因码(P0xx/V0xx) + 明细`。
- **乱序**：窗口按事件时间向下取整归属；窗口关闭前乱序事件一律计入，证据按事件时间排序。
- **迟到**：只有「事件所属窗口已被 watermark finalize」才算迟到；迟到只登记、不触发/复活告警。
- **重复**：接入层按 `来源+来源记录ID`（无 ID 则报文指纹）去重；窗口内按 eventId 去重；
  告警按 correlationKey 幂等。三层去重保证重复消费零新告警。
- **并发**：流水线批次锁 + 告警同链锁串行化写入，保证并发下告警数量与状态精确一致。

更详细的规则模型、窗口/watermark 语义、告警状态流转见 [`docs/DETECTION_MODEL.md`](docs/DETECTION_MODEL.md)。
