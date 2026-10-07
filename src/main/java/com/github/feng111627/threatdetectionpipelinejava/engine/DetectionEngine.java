package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleSet;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 检测引擎：对归一化事件执行全部启用规则，维护每条规则的 watermark，
 * 并在 watermark 推进时关闭过期窗口。
 *
 * <p>规则按 ID 索引：同一 ID 的规则换版本后沿用窗口（版本仅固化到告警上），
 * 这样在「规则调整」时历史窗口结论与新规则产出都能解释。
 */
@Component
public class DetectionEngine {

    private final WindowManager windowManager;
    private final Clock clock;

    /** 每条规则观测到的最大事件时间（毫秒），用于生成 watermark。 */
    private final ConcurrentMap<String, Long> maxEventTimeMsByRule = new ConcurrentHashMap<>();

    public DetectionEngine(WindowManager windowManager, Clock clock) {
        this.windowManager = windowManager;
        this.clock = clock;
    }

    /**
     * 处理一条归一化事件，返回本次新触发的告警种子。
     */
    public List<AlertSeed> process(NormalizedEvent event, RuleSet ruleSet) {
        List<AlertSeed> produced = new ArrayList<>();
        for (DetectionRule rule : ruleSet.rules()) {
            if (!rule.enabled()) {
                continue;
            }
            long eventMs = event.eventTime().toEpochMilli();
            long newMax = maxEventTimeMsByRule.merge(rule.id(), eventMs, Math::max);

            Duration lateness = Duration.ofSeconds(rule.allowedLatenessSeconds());
            // watermark 可能因为乱序事件而回退；迟到判定只与「曾经见过的最大时间」有关
            long watermarkMs = Math.max(0L, newMax - lateness.toMillis());
            Instant ruleWatermark = Instant.ofEpochMilli(watermarkMs);

            EngineOutcome outcome = windowManager.addEvent(rule, event, ruleWatermark);
            produced.addAll(outcome.seeds());

            windowManager.closeExpiredWindows(ruleWatermark);
        }
        return List.copyOf(produced);
    }

    /**
     * 按当前系统时间推进全部规则的 watermark 并关闭过期窗口。
     * 批处理结束后调用，保证基于 wall-clock 的窗口能及时收尾。
     */
    public List<AlertSeed> flush(RuleSet ruleSet) {
        Instant now = Instant.now(clock);
        for (DetectionRule rule : ruleSet.rules()) {
            windowManager.closeExpiredWindows(now);
        }
        return List.of();
    }

    /** 重置引擎状态（主要用于测试隔离）。 */
    public void reset() {
        maxEventTimeMsByRule.clear();
    }
}
