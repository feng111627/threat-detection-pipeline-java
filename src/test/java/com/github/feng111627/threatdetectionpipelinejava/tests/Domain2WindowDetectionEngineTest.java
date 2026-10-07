package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.engine.AlertSeed;
import com.github.feng111627.threatdetectionpipelinejava.engine.DetectionEngine;
import com.github.feng111627.threatdetectionpipelinejava.engine.EngineOutcome;
import com.github.feng111627.threatdetectionpipelinejava.engine.WindowManager;
import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.Severity;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleSet;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域二：可配置规则与基于窗口的关联（阈值/频率/时序、乱序/迟到/重复）。
 */
class Domain2WindowDetectionEngineTest extends BusinessTestBase {

    private static final Instant T0 = Instant.parse("2026-10-07T10:00:00Z");
    private DetectionEngine engine;

    @BeforeAll
    static void header() {
        System.out.println("========== 业务域二：窗口关联与规则检测 ==========");
    }

    @BeforeEach
    void setUp() {
        engine = new DetectionEngine(
                new WindowManager(Clock.fixed(T0, ZoneOffset.UTC)),
                Clock.fixed(T0, ZoneOffset.UTC));
    }

    private DetectionRule thresholdRule(int threshold, long windowSec, long latenessSec, List<String> groupBy) {
        return new DetectionRule("R-TH", "v1", true, RuleType.THRESHOLD,
                "LOGIN_FAIL", null, Map.of(), threshold, windowSec, latenessSec,
                List.of(), groupBy, Severity.HIGH, "阈值规则");
    }

    private DetectionRule sequenceRule(long windowSec, long latenessSec) {
        return new DetectionRule("R-SEQ", "v1", true, RuleType.SEQUENCE,
                null, null, Map.of(), 3, windowSec, latenessSec,
                List.of("LOGIN_SUCCESS", "PRIVILEGE_ESCALATION", "DATA_EXPORT"),
                List.of("sourceIp"), Severity.CRITICAL, "时序规则");
    }

    private RuleSet rules(DetectionRule... rules) {
        return new RuleSet("test-v1", T0, List.of(rules));
    }

    private NormalizedEvent event(String id, String type, String ip, long offsetSec) {
        return new NormalizedEvent(id, "iam", id, type, ip, null, null,
                T0.plusSeconds(offsetSec), T0, Map.of());
    }

    /** 依次把事件喂给引擎，收集所有触发的种子。 */
    private List<AlertSeed> feed(RuleSet set, NormalizedEvent... events) {
        List<AlertSeed> seeds = new ArrayList<>();
        for (NormalizedEvent e : events) {
            EngineOutcome outcome = engine.process(e, set);
            seeds.addAll(outcome.seeds());
        }
        return seeds;
    }

    @Test
    @Order(1)
    @DisplayName("用例2.01 阈值规则：窗口内事件数达到阈值才触发一次")
    void thresholdFiresOnce() {
        RuleSet set = rules(thresholdRule(3, 60, 10, List.of("sourceIp")));
        List<AlertSeed> seeds = feed(set,
                event("a1", "LOGIN_FAIL", "9.9.9.9", 1),
                event("a2", "LOGIN_FAIL", "9.9.9.9", 2));
        assertTrue(seeds.isEmpty(), "未达阈值不应触发");
        seeds = feed(set, event("a3", "LOGIN_FAIL", "9.9.9.9", 3));
        assertEquals(1, seeds.size());
        // 再来一条不重复触发
        seeds = feed(set, event("a4", "LOGIN_FAIL", "9.9.9.9", 4));
        assertTrue(seeds.isEmpty(), "同一窗口已触发，不应重复产出");
    }

    @Test
    @Order(2)
    @DisplayName("用例2.02 乱序到达不影响判定：最晚到齐时触发，证据按事件时间有序")
    void outOfOrderStillFires() {
        RuleSet set = rules(thresholdRule(3, 60, 30, List.of("sourceIp")));
        List<AlertSeed> seeds = feed(set,
                event("b3", "LOGIN_FAIL", "8.8.8.8", 30),
                event("b1", "LOGIN_FAIL", "8.8.8.8", 10),
                event("b2", "LOGIN_FAIL", "8.8.8.8", 20));
        assertEquals(1, seeds.size(), "乱序到达在到齐时应触发一次");
        List<String> ids = seeds.get(0).eventIds();
        assertEquals(List.of("b1", "b2", "b3"), ids, "证据事件必须按事件时间排序");
    }

    @Test
    @Order(3)
    @DisplayName("用例2.03 重复到达的事件不改变计数，不重复产出告警")
    void duplicateEventsIgnored() {
        RuleSet set = rules(thresholdRule(2, 60, 30, List.of("sourceIp")));
        List<AlertSeed> seeds = new ArrayList<>();
        NormalizedEvent e1 = event("c1", "LOGIN_FAIL", "7.7.7.7", 5);
        NormalizedEvent e2 = event("c2", "LOGIN_FAIL", "7.7.7.7", 6);
        seeds.addAll(feed(set, e1, e1, e1));
        seeds.addAll(feed(set, e2, e1));
        assertEquals(1, seeds.size(), "重复事件不计入，到达两条不同事件时触发一次");
    }

    @Test
    @Order(4)
    @DisplayName("用例2.04 迟到事件（窗口已关闭）被标记且不触发/复活告警")
    void lateEventAfterWindowClose() {
        RuleSet set = rules(thresholdRule(3, 60, 0, List.of("sourceIp")));
        // 先凑齐 3 条并用更晚事件把 watermark 推过窗口结束点
        feed(set,
                event("d1", "LOGIN_FAIL", "6.6.6.6", 1),
                event("d2", "LOGIN_FAIL", "6.6.6.6", 2),
                event("d3", "LOGIN_FAIL", "6.6.6.6", 3));
        // 推进 watermark 到 120s，关闭 [0,60) 窗口
        feed(set, event("d-future", "LOGIN_FAIL", "6.6.6.6", 120));
        // 极晚事件回到已关闭窗口
        EngineOutcome late = engine.process(event("d-late", "LOGIN_FAIL", "6.6.6.6", 10), set);
        assertTrue(late.isLate(), "应判定为迟到");
        assertTrue(late.seeds().isEmpty(), "迟到事件不得触发告警");
    }

    @Test
    @Order(5)
    @DisplayName("用例2.05 不同分组互不影响：A 组触发不影响 B 组计数")
    void differentGroupsIsolated() {
        RuleSet set = rules(thresholdRule(2, 60, 10, List.of("sourceIp")));
        List<AlertSeed> seeds = feed(set,
                event("g1", "LOGIN_FAIL", "1.1.1.1", 1),
                event("g2", "LOGIN_FAIL", "1.1.1.1", 2),
                event("h1", "LOGIN_FAIL", "2.2.2.2", 1));
        assertEquals(1, seeds.size());
        assertEquals("1.1.1.1", seeds.get(0).correlationKey().split("\\|")[2]);
        assertFalse(feed(set, event("h2", "LOGIN_FAIL", "2.2.2.2", 2)).isEmpty(),
                "B 组达到阈值应独立触发");
    }

    @Test
    @Order(6)
    @DisplayName("用例2.06 跨窗口事件分别计数：不同窗口起始只影响各自窗口")
    void separateWindows() {
        RuleSet set = rules(thresholdRule(2, 60, 0, List.of("sourceIp")));
        List<AlertSeed> seeds = feed(set,
                event("w1", "LOGIN_FAIL", "5.5.5.5", 10),
                event("w2", "LOGIN_FAIL", "5.5.5.5", 20),
                event("w3", "LOGIN_FAIL", "5.5.5.5", 70));
        assertEquals(1, seeds.size(), "只有第一个窗口达到阈值");
    }

    @Test
    @Order(7)
    @DisplayName("用例2.07 时序规则：乱序到达仍按事件时间识别出完整序列")
    void sequenceOutOfOrder() {
        RuleSet set = rules(sequenceRule(300, 30));
        NormalizedEvent login = event("s1", "LOGIN_SUCCESS", "3.3.3.3", 0);
        NormalizedEvent priv = event("s2", "PRIVILEGE_ESCALATION", "3.3.3.3", 30);
        NormalizedEvent export = event("s3", "DATA_EXPORT", "3.3.3.3", 60);
        // 逆序发送
        List<AlertSeed> seeds = feed(set, export, priv, login);
        assertEquals(1, seeds.size());
        assertEquals(List.of("s1", "s2", "s3"), seeds.get(0).eventIds());
    }

    @Test
    @Order(8)
    @DisplayName("用例2.08 时序规则：序列不完整不触发")
    void sequenceIncomplete() {
        RuleSet set = rules(sequenceRule(300, 30));
        List<AlertSeed> seeds = feed(set,
                event("s1", "LOGIN_SUCCESS", "4.4.4.4", 0),
                event("s2", "DATA_EXPORT", "4.4.4.4", 60));
        assertTrue(seeds.isEmpty());
    }

    @Test
    @Order(9)
    @DisplayName("用例2.09 被禁用的规则不产出任何结果")
    void disabledRuleSkipped() {
        DetectionRule disabled = new DetectionRule("R-OFF", "v1", false, RuleType.THRESHOLD,
                "LOGIN_FAIL", null, Map.of(), 1, 60, 10, List.of(), List.of("sourceIp"),
                Severity.LOW, "关闭的规则");
        RuleSet set = rules(disabled);
        List<AlertSeed> seeds = feed(set, event("z1", "LOGIN_FAIL", "1.2.3.4", 1));
        assertTrue(seeds.isEmpty());
    }

    @Test
    @Order(10)
    @DisplayName("用例2.10 同一批数据重复消费：窗口内不再产生第二个种子")
    void replayBatchNoDuplicateSeed() {
        RuleSet set = rules(thresholdRule(2, 60, 30, List.of("sourceIp")));
        NormalizedEvent[] batch = {
                event("r1", "LOGIN_FAIL", "9.9.9.9", 1),
                event("r2", "LOGIN_FAIL", "9.9.9.9", 2)
        };
        assertEquals(1, feed(set, batch).size());
        // 引擎级重复消费：事件 ID 在窗口内去重，不产生新种子
        List<AlertSeed> replay = feed(set, batch);
        assertEquals(0, replay.size());
    }
}
