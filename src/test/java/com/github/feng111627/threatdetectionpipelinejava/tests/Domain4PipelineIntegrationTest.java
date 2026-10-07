package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.alert.AlertService;
import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.AlertStatus;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.DetectionPipeline;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.PipelineResult;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleRepository;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleSet;
import com.github.feng111627.threatdetectionpipelinejava.simulator.LocalEventSimulator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域四：端到端链路（接入->检测->告警）在
 * 并发接入、乱序/迟到、重复消费、规则调整 四类场景下的稳定性与可解释性。
 */
@SpringBootTest(properties = "spring.main.web-application-type=none")
class Domain4PipelineIntegrationTest extends BusinessTestBase {

    private static final Instant T0 = Instant.parse("2026-10-07T11:00:00Z");

    @Autowired
    private DetectionPipeline pipeline;
    @Autowired
    private LocalEventSimulator simulator;
    @Autowired
    private RuleRepository ruleRepository;
    @Autowired
    private AlertService alertService;

    @BeforeAll
    static void header() {
        System.out.println("========== 业务域四：端到端链路（并发/乱序/重复/规则调整） ==========");
    }

    @BeforeEach
    void reset() {
        // 回到默认规则并清空内存状态，保证用例彼此隔离
        ruleRepository.load("rules-default.json");
        pipeline.reset();
    }

    private RawEvent kvLoginFail(String id, String user, String ip, long offsetSec) {
        String payload = "event_id=" + id + ";type=LOGIN_FAIL;ts=" + T0.plusSeconds(offsetSec)
                + ";user=" + user + ";src_ip=" + ip;
        return new RawEvent("iam", id, payload, T0);
    }

    @Test
    @Order(1)
    @DisplayName("用例4.01 暴力破解场景端到端：乱序到齐产出 1 条告警，迟到事件不计入")
    void endToEndBruteForceOutOfOrderAndLate() {
        List<RawEvent> batch = new ArrayList<>();
        // 6 条同 user/ip 的 LOGIN_FAIL，顺序故意打乱；阈值 5、窗口 60s、迟到宽限 30s
        long[] offsets = {45, 5, 30, 10, 50, 20};
        int i = 1;
        for (long off : offsets) {
            batch.add(kvLoginFail("bf-" + i, "root", "198.51.100.7", off));
            i++;
        }
        // 一条极晚事件：先推进 watermark 再回到已关闭窗口
        batch.add(kvLoginFail("bf-clock", "root", "198.51.100.7", 300));
        batch.add(kvLoginFail("bf-late", "root", "198.51.100.7", 2));

        PipelineResult result = pipeline.processBatch(batch);
        long bfAlerts = result.alerts().stream()
                .filter(a -> a.ruleId().equals("R-LOGIN-BRUTE-FORCE")).count();
        assertEquals(1, bfAlerts, "乱序到齐应恰好触发 1 条暴力破解告警");
        assertTrue(result.late().size() >= 1, "极晚事件应被标记为迟到: " + result.late());

        Alert alert = result.alerts().stream()
                .filter(a -> a.ruleId().equals("R-LOGIN-BRUTE-FORCE")).findFirst().orElseThrow();
        assertEquals(5, alert.eventIds().size(), "告警证据应包含阈值数量的事件");
        assertEquals("2026-10-07-v1", alert.ruleVersion());
    }

    @Test
    @Order(2)
    @DisplayName("用例4.02 乱序攻击链端到端：逆序发送仍能按事件时间完成时序关联")
    void endToEndKillChainReordered() {
        List<RawEvent> chain = simulator.generateScenario(LocalEventSimulator.SCENARIO_KILL_CHAIN);
        PipelineResult result = pipeline.processBatch(chain);
        long seqAlerts = result.alerts().stream()
                .filter(a -> a.ruleId().equals("R-KILL-CHAIN")).count();
        assertEquals(1, seqAlerts);
        Alert alert = result.alerts().get(0);
        // 证据按事件时间：登录 -> 提权 -> 外发，即使接入顺序相反
        assertEquals(List.of("iam:kc-1", "edr:kc-2", "firewall:kc-3"), alert.eventIds());
    }

    @Test
    @Order(3)
    @DisplayName("用例4.03 同一批数据重复消费：第二次零新增、零新告警，结论可复现")
    void replayBatchIsIdempotent() {
        List<RawEvent> batch = simulator.generateScenario(LocalEventSimulator.SCENARIO_BRUTE_FORCE);
        PipelineResult first = pipeline.processBatch(batch);
        assertTrue(first.alerts().size() >= 1, "首次消费应产出告警");
        int firstTotal = alertService.allAlerts().size();

        PipelineResult second = pipeline.processBatch(batch);
        assertEquals(0, second.accepted().size(), "重复消费没有新事件接入");
        assertEquals(batch.size(), second.rejected().size(), "重复记录全部以 V007 拒绝");
        assertTrue(second.rejected().stream()
                .allMatch(r -> r.reason() == RejectionReason.DUPLICATE_EVENT));
        assertEquals(0, second.alerts().size(), "重复消费不得产生新告警");
        assertEquals(firstTotal, alertService.allAlerts().size(), "告警总数保持不变");
    }

    @Test
    @Order(4)
    @DisplayName("用例4.04 并发接入：多线程同时提交批次，告警数量与状态始终一致")
    void concurrentIngestionConsistent() throws InterruptedException {
        int threadCount = 16;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();
        Map<Integer, List<RawEvent>> perThread = new ConcurrentHashMap<>();

        for (int t = 0; t < threadCount; t++) {
            final int idx = t;
            // 每个线程负责一个独立 IP 的 5 次失败（各应触发 1 条）
            List<RawEvent> events = new ArrayList<>();
            String ip = "10.10." + idx + ".1";
            for (int k = 1; k <= 5; k++) {
                events.add(kvLoginFail("t" + idx + "-" + k, "u" + idx, ip, k));
            }
            perThread.put(idx, events);
        }

        for (int t = 0; t < threadCount; t++) {
            final int idx = t;
            pool.submit(() -> {
                try {
                    start.await();
                    PipelineResult r = pipeline.processBatch(perThread.get(idx));
                    if (r.alerts().size() != 1) {
                        failures.add(new AssertionError("线程 " + idx
                                + " 应恰好新产出 1 条，实际 " + r.alerts().size()));
                    }
                } catch (Throwable e) {
                    failures.add(e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();

        assertTrue(failures.isEmpty(), "并发处理不应有失败: " + failures);
        long bfAlerts = alertService.allAlerts().stream()
                .filter(a -> a.ruleId().equals("R-LOGIN-BRUTE-FORCE")).count();
        assertEquals(threadCount, bfAlerts, "每个 IP 恰好一条，并发下总数必须精确");
        assertTrue(alertService.allAlerts().stream()
                .allMatch(a -> a.status() == AlertStatus.NEW));
    }

    @Test
    @Order(5)
    @DisplayName("用例4.05 并发重复消费：相同批次被多线程重复提交，不产生重复告警")
    void concurrentReplayNoDuplicates() throws InterruptedException {
        List<RawEvent> batch = new ArrayList<>();
        for (int k = 1; k <= 5; k++) {
            batch.add(kvLoginFail("dup-" + k, "shared", "172.16.0.9", k));
        }
        int threadCount = 12;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        for (int t = 0; t < threadCount; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    pipeline.processBatch(batch);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();
        long count = alertService.allAlerts().stream()
                .filter(a -> a.ruleId().equals("R-LOGIN-BRUTE-FORCE")).count();
        assertEquals(1, count, "同一批并发重复消费只能有一条告警");
    }

    @Test
    @Order(6)
    @DisplayName("用例4.06 规则调整：上调阈值后旧数据不再触发，历史告警仍固化旧版本可复现")
    void ruleAdjustmentThresholdAndHistoryReproducible() {
        // v1 阈值 3 可以触发
        List<RawEvent> threeBlocks = new ArrayList<>();
        for (int k = 0; k < 3; k++) {
            String payload = "{\"event_id\":\"fw-" + k + "\",\"type\":\"FIREWALL_BLOCK\","
                    + "\"ts\":\"" + T0.plusSeconds(k * 10) + "\",\"src_ip\":\"203.0.113.9\"}";
            threeBlocks.add(new RawEvent("firewall", "fw-" + k, payload, T0));
        }
        PipelineResult v1Result = pipeline.processBatch(threeBlocks);
        assertEquals(1, v1Result.alerts().size());
        Alert historical = v1Result.alerts().get(0);
        assertEquals("2026-10-07-v1", historical.ruleVersion());

        // 调整为 v2（阈值 4），并用全新数据：同样 3 条不再触发
        RuleSet v2 = ruleRepository.load("rules-v2.json");
        assertEquals("2026-10-07-v2", v2.version());
        pipeline.reset(); // 清空引擎与告警，模拟用新规则对新数据重新评估
        List<RawEvent> threeBlocksNew = new ArrayList<>();
        for (int k = 0; k < 3; k++) {
            String id = "fw2-" + k;
            String payload = "{\"event_id\":\"" + id + "\",\"type\":\"FIREWALL_BLOCK\","
                    + "\"ts\":\"" + T0.plusSeconds(k * 10) + "\",\"src_ip\":\"198.51.100.1\"}";
            threeBlocksNew.add(new RawEvent("firewall", id, payload, T0));
        }
        PipelineResult v2Result = pipeline.processBatch(threeBlocksNew);
        assertFalse(v2Result.alerts().stream()
                .anyMatch(a -> a.ruleId().equals("R-FW-BLOCK-BRUST")), "阈值上调后 3 条不应触发");

        // 历史仓库保留了 v1 快照，历史告警的规则版本仍可追溯复现
        assertTrue(ruleRepository.history().stream().anyMatch(rs -> rs.version().equals("2026-10-07-v1")));
        assertEquals("2026-10-07-v1", historical.ruleVersion());
    }

    @Test
    @Order(7)
    @DisplayName("用例4.07 规则调整：v2 启用此前关闭的恶意软件规则后，相同事件可以触发")
    void ruleAdjustmentEnablesDisabledRule() {
        // v1 中 R-MALWARE 默认关闭
        List<RawEvent> malware = List.of(
                new RawEvent("edr", "m1", "m1,MALWARE_DETECTED," + T0.getEpochSecond()
                        + ",10.0.0.7,,,HIGH", T0));
        // CSV 时间戳用空格格式更贴近真实，这里用 ISO 会被判非法，改用空格格式
        malware = List.of(new RawEvent("edr", "m1",
                "m1,MALWARE_DETECTED,2026-10-07 11:00:05,10.0.0.7,,,HIGH", T0));
        PipelineResult v1Result = pipeline.processBatch(malware);
        assertTrue(v1Result.alerts().isEmpty(), "规则关闭时不应产出告警");

        ruleRepository.load("rules-v2.json");
        pipeline.reset();
        PipelineResult v2Result = pipeline.processBatch(malware);
        assertEquals(1, v2Result.alerts().size(), "规则启用后应产出告警");
        assertEquals("R-MALWARE", v2Result.alerts().get(0).ruleId());
        assertEquals("2026-10-07-v2", v2Result.alerts().get(0).ruleVersion());
    }
}
