package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.Severity;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 检测引擎产出的告警种子（尚未落库），交由 AlertService 去重与落库。
 */
public record AlertSeed(
        String ruleId,
        String ruleVersion,
        String correlationKey,
        Severity severity,
        String title,
        Instant firstEventTime,
        Instant triggerTime,
        List<String> eventIds,
        Map<String, Object> evidence) {
}
