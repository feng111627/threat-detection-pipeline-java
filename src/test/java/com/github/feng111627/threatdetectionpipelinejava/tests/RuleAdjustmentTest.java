package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.alert.Alert;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStore;
import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务场景：规则调整后历史结论可复现。
 * 告警记录命中时的规则版本；版本升级重置窗口但不清除历史告警。
 */
class RuleAdjustmentTest {

    private static final Instant BASE = Instant.parse("2026-10-07T08:00:00Z");

    private SecurityEvent loginFailed(String id, long offsetSeconds, String user) {
        return new SecurityEvent(id, "TEST", EventType.LOGIN_FAILED,
                BASE.plusSeconds(offsetSeconds), "host1", user, Map.of());
    }

    private DetectionRule bruteForce(int version, int threshold) {
        return DetectionRule.frequency("R-BRUTE", version,
                Set.of(EventType.LOGIN_FAILED), threshold, Duration.ofMinutes(5), "user");
    }

    @Test
    @DisplayName("规则版本随告警固化，调整后历史结论可复现")
    void alertsKeepRuleVersionForReplay() {
        AlertStore store = new AlertStore();
        RuleEngine engine = new RuleEngine();

        // v1：阈值 3，两条事件不命中
        engine.loadRules(List.of(bruteForce(1, 3)));
        engine.evaluate(loginFailed("e1", 0, "alice")).forEach(store::upsert);
        engine.evaluate(loginFailed("e2", 10, "alice")).forEach(store::upsert);
        assertEquals(0, store.count());

        // 调整为 v2：阈值 2，窗口重置后同样的两条事件命中
        engine.loadRules(List.of(bruteForce(2, 2)));
        engine.evaluate(loginFailed("e3", 0, "alice")).forEach(store::upsert);
        engine.evaluate(loginFailed("e4", 10, "alice")).forEach(store::upsert);
        assertEquals(1, store.count());
        assertEquals(2, store.findAll().get(0).ruleVersion());

        // 复现：用 v1 规则重放 e1,e2 仍不命中；用 v2 重放则命中 —— 结论可复现
        RuleEngine replayV1 = new RuleEngine();
        replayV1.loadRules(List.of(bruteForce(1, 3)));
        assertTrue(replayV1.evaluate(loginFailed("r1", 0, "alice")).isEmpty());
        assertTrue(replayV1.evaluate(loginFailed("r2", 10, "alice")).isEmpty());

        RuleEngine replayV2 = new RuleEngine();
        replayV2.loadRules(List.of(bruteForce(2, 2)));
        replayV2.evaluate(loginFailed("r3", 0, "alice"));
        assertEquals(1, replayV2.evaluate(loginFailed("r4", 10, "alice")).size());
        TestLog.pass("规则调整可复现", "告警固化规则版本，重放结果与历史一致");
    }

    @Test
    @DisplayName("同版本重复加载不重置窗口，版本变化才重置")
    void reloadSameVersionKeepsState() {
        RuleEngine engine = new RuleEngine();
        engine.loadRules(List.of(bruteForce(1, 2)));
        assertTrue(engine.evaluate(loginFailed("e1", 0, "alice")).isEmpty());

        // 同版本重复加载：窗口状态保留，第二条事件到达即命中
        engine.loadRules(List.of(bruteForce(1, 2)));
        assertEquals(1, engine.evaluate(loginFailed("e2", 10, "alice")).size());

        // 版本升级：窗口重置，需要重新累计
        engine.loadRules(List.of(bruteForce(2, 2)));
        assertTrue(engine.evaluate(loginFailed("e3", 20, "alice")).isEmpty());
        assertEquals(1, engine.evaluate(loginFailed("e4", 30, "alice")).size());
        TestLog.pass("规则调整可复现", "同版本加载保留状态，版本升级重置窗口");
    }
}
