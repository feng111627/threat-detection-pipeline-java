package com.github.feng111627.threatdetectionpipelinejava.alert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 告警实体：去重键为 (ruleId, chainKey)，同一事件链的后续命中合并进同一条告警。
 * ruleVersion 记录命中时的规则版本，规则调整后历史结论仍可复现。
 * 所有变更方法加锁，保证并发接入时数量与状态一致。
 */
public class Alert {

    private final String alertId;
    private final String ruleId;
    private final String chainKey;
    private final Instant createdAt;
    private int ruleVersion;
    private AlertStatus status = AlertStatus.NEW;
    private final Set<String> eventIds = new LinkedHashSet<>();
    private final List<StatusChange> history = new ArrayList<>();
    private int hitCount = 0;
    private Instant lastMergeAt;

    public Alert(String alertId, String ruleId, int ruleVersion, String chainKey) {
        this.alertId = alertId;
        this.ruleId = ruleId;
        this.ruleVersion = ruleVersion;
        this.chainKey = chainKey;
        this.createdAt = Instant.now();
    }

    public synchronized String alertId() { return alertId; }
    public synchronized String ruleId() { return ruleId; }
    public synchronized int ruleVersion() { return ruleVersion; }
    public synchronized String chainKey() { return chainKey; }
    public synchronized AlertStatus status() { return status; }
    public synchronized Set<String> eventIds() { return Set.copyOf(eventIds); }
    public synchronized List<StatusChange> history() { return List.copyOf(history); }
    public synchronized int hitCount() { return hitCount; }
    public synchronized Instant createdAt() { return createdAt; }
    public synchronized Instant lastMergeAt() { return lastMergeAt; }

    /** 同链命中合并：累计事件与命中次数，规则版本取最新。 */
    public synchronized void merge(int newRuleVersion, Iterable<String> newEventIds) {
        newEventIds.forEach(eventIds::add);
        this.ruleVersion = Math.max(this.ruleVersion, newRuleVersion);
        this.hitCount++;
        this.lastMergeAt = Instant.now();
    }

    /** 状态流转：非法流转直接抛错，合法流转写入审计历史。 */
    public synchronized void transition(AlertStatus next, String reason) {
        if (!status.canTransitionTo(next)) {
            throw new IllegalStateException(
                    "非法状态流转: %s -> %s (告警 %s)".formatted(status, next, alertId));
        }
        history.add(new StatusChange(status, next, Instant.now(), reason));
        this.status = next;
    }
}
