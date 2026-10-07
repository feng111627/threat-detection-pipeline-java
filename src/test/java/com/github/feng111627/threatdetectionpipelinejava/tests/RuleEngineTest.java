package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.AlertCandidate;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务场景：窗口关联检测在乱序、迟到、重复到达下结果稳定。
 */
class RuleEngineTest {

    private static final Instant BASE = Instant.parse("2026-10-07T08:00:00Z");

    private SecurityEvent event(String id, EventType type, long offsetSeconds, String user) {
        return new SecurityEvent(id, "TEST", type, BASE.plusSeconds(offsetSeconds),
                "host1", user, Map.of());
    }

    private RuleEngine frequencyEngine(int threshold) {
        RuleEngine engine = new RuleEngine();
        engine.loadRules(List.of(DetectionRule.frequency("R-FREQ", 1,
                Set.of(EventType.LOGIN_FAILED), threshold, Duration.ofMinutes(5), "user")));
        return engine;
    }

    private List<AlertCandidate> feedAll(RuleEngine engine, List<SecurityEvent> events) {
        List<AlertCandidate> hits = new ArrayList<>();
        events.forEach(e -> hits.addAll(engine.evaluate(e)));
        return hits;
    }

    @Test
    @DisplayName("频率规则：窗口内达到阈值命中一次")
    void frequencyFiresOnceAtThreshold() {
        RuleEngine engine = frequencyEngine(3);
        List<SecurityEvent> events = List.of(
                event("e1", EventType.LOGIN_FAILED, 0, "alice"),
                event("e2", EventType.LOGIN_FAILED, 10, "alice"),
                event("e3", EventType.LOGIN_FAILED, 20, "alice"),
                event("e4", EventType.LOGIN_FAILED, 30, "alice"));
        List<AlertCandidate> hits = feedAll(engine, events);
        assertEquals(1, hits.size());
        assertEquals("R-FREQ|alice", hits.get(0).chainKey());
        TestLog.pass("窗口关联检测", "频率规则达阈值命中一次");
    }

    @Test
    @DisplayName("乱序到达：最终判定与顺序到达一致")
    void outOfOrderYieldsSameResult() {
        List<SecurityEvent> inOrder = List.of(
                event("e1", EventType.LOGIN_FAILED, 0, "alice"),
                event("e2", EventType.LOGIN_FAILED, 10, "alice"),
                event("e3", EventType.LOGIN_FAILED, 20, "alice"),
                event("e4", EventType.LOGIN_FAILED, 400, "alice"),
                event("e5", EventType.LOGIN_FAILED, 410, "alice"),
                event("e6", EventType.LOGIN_FAILED, 420, "alice"));
        List<SecurityEvent> shuffled = new ArrayList<>(inOrder);
        Collections.shuffle(shuffled, new java.util.Random(42));

        List<AlertCandidate> orderedHits = feedAll(frequencyEngine(3), inOrder);
        List<AlertCandidate> shuffledHits = feedAll(frequencyEngine(3), shuffled);

        // 两个窗口周期各命中一次，乱序不影响最终告警数与事件链
        assertEquals(orderedHits.size(), shuffledHits.size());
        assertEquals(2, shuffledHits.size());
        assertTrue(shuffledHits.stream().allMatch(h -> h.chainKey().equals("R-FREQ|alice")));
        TestLog.pass("窗口关联检测", "乱序到达判定结果与顺序一致");
    }

    @Test
    @DisplayName("迟到事件：补齐窗口后命中时序规则")
    void lateEventCompletesSequence() {
        RuleEngine engine = new RuleEngine();
        engine.loadRules(List.of(DetectionRule.sequence("R-SEQ", 1,
                List.of(EventType.LOGIN_FAILED, EventType.LOGIN_SUCCESS, EventType.PROCESS_START),
                Duration.ofMinutes(10), "user")));

        // 中间的 LOGIN_SUCCESS 最后才到（迟到），到达后应重估并命中
        assertTrue(engine.evaluate(event("e1", EventType.LOGIN_FAILED, 0, "bob")).isEmpty());
        assertTrue(engine.evaluate(event("e3", EventType.PROCESS_START, 20, "bob")).isEmpty());
        List<AlertCandidate> hits = engine.evaluate(event("e2", EventType.LOGIN_SUCCESS, 10, "bob"));
        assertEquals(1, hits.size());
        assertEquals(List.of("e1", "e2", "e3"), hits.get(0).eventIds());
        TestLog.pass("窗口关联检测", "迟到事件补齐时序后命中");
    }

    @Test
    @DisplayName("重复事件：窗口内按 eventId 去重不影响计数")
    void duplicateEventsDoNotDoubleCount() {
        RuleEngine engine = frequencyEngine(3);
        SecurityEvent e1 = event("e1", EventType.LOGIN_FAILED, 0, "alice");
        assertTrue(engine.evaluate(e1).isEmpty());
        assertTrue(engine.evaluate(e1).isEmpty()); // 重复到达
        assertTrue(engine.evaluate(event("e2", EventType.LOGIN_FAILED, 10, "alice")).isEmpty());
        // 若重复计数此处早已误报；实际需第三个不同事件才命中
        List<AlertCandidate> hits = engine.evaluate(event("e3", EventType.LOGIN_FAILED, 20, "alice"));
        assertEquals(1, hits.size());
        TestLog.pass("窗口关联检测", "重复事件不重复计数");
    }

    @Test
    @DisplayName("阈值规则：数值属性达到阈值命中")
    void thresholdRuleOnNumericAttribute() {
        RuleEngine engine = new RuleEngine();
        engine.loadRules(List.of(DetectionRule.threshold("R-THRESH", 1,
                Set.of(EventType.PORT_SCAN), 10, Duration.ofMinutes(1), "host", "ports")));

        SecurityEvent small = new SecurityEvent("s1", "TEST", EventType.PORT_SCAN,
                BASE, "fw1", null, Map.of("ports", "5"));
        SecurityEvent big = new SecurityEvent("s2", "TEST", EventType.PORT_SCAN,
                BASE.plusSeconds(5), "fw1", null, Map.of("ports", "20"));
        assertTrue(engine.evaluate(small).isEmpty());
        List<AlertCandidate> hits = engine.evaluate(big);
        assertEquals(1, hits.size());
        assertEquals("R-THRESH|fw1", hits.get(0).chainKey());
        TestLog.pass("窗口关联检测", "阈值规则按数值属性命中");
    }

    @Test
    @DisplayName("窗口外事件不计入：超出窗口的旧事件被驱逐")
    void eventsOutsideWindowAreExcluded() {
        RuleEngine engine = frequencyEngine(3);
        assertTrue(engine.evaluate(event("e1", EventType.LOGIN_FAILED, 0, "alice")).isEmpty());
        assertTrue(engine.evaluate(event("e2", EventType.LOGIN_FAILED, 10, "alice")).isEmpty());
        // 6 分钟后的事件已超出 5 分钟窗口，窗口内只剩自己，不应命中
        assertTrue(engine.evaluate(event("e3", EventType.LOGIN_FAILED, 360, "alice")).isEmpty());
        TestLog.pass("窗口关联检测", "窗口外事件不计入判定");
    }
}
