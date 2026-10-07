package com.github.feng111627.threatdetectionpipelinejava.alert;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * 告警状态及合法流转表。
 */
public enum AlertStatus {
    NEW,
    ACKNOWLEDGED,
    RESOLVED,
    SUPPRESSED;

    private static final Map<AlertStatus, Set<AlertStatus>> LEGAL = Map.of(
            NEW, EnumSet.of(ACKNOWLEDGED, SUPPRESSED),
            ACKNOWLEDGED, EnumSet.of(RESOLVED, SUPPRESSED),
            RESOLVED, EnumSet.noneOf(AlertStatus.class),
            SUPPRESSED, EnumSet.noneOf(AlertStatus.class));

    public boolean canTransitionTo(AlertStatus next) {
        return LEGAL.getOrDefault(this, Set.of()).contains(next);
    }
}
