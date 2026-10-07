package com.github.feng111627.threatdetectionpipelinejava.rule;

import java.util.List;

/**
 * 规则命中后产出的告警候选，携带命中的规则版本与事件链。
 */
public record AlertCandidate(
        String ruleId,
        int ruleVersion,
        String chainKey,
        List<String> eventIds,
        String description) {
}
