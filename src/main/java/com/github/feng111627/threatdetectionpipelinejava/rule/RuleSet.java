package com.github.feng111627.threatdetectionpipelinejava.rule;
import java.time.Instant;

import java.util.List;

/**
 * 某一版本下生效的规则集合（不可变快照）。
 */
public record RuleSet(String version, Instant loadedAt, List<DetectionRule> rules) {

    public RuleSet {
        rules = rules == null ? List.of() : List.copyOf(rules);
    }
}
