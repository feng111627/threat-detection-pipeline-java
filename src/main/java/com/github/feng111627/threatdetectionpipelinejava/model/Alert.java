package com.github.feng111627.threatdetectionpipelinejava.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 告警。规则版本固化在告警上，保证规则调整后历史结论仍可复现。
 * 状态的合法性由 AlertService 校验，本类承载数据、合并内容与流转历史。
 */
public class Alert {

    private final String alertId;
    private final String ruleId;
    private final String ruleVersion;
    private final String correlationKey;
    private final Severity severity;
    private final String title;
    private final Instant firstEventTime;
    private final Instant triggerTime;
    private final List<String> eventIds = new ArrayList<>();
    private final Map<String, Object> evidence = new LinkedHashMap<>();
    private final List<AlertTransition> history = new ArrayList<>();

    private AlertStatus status;
    private String mergedInto;

    public Alert(String alertId, String ruleId, String ruleVersion, String correlationKey,
                 Severity severity, String title, Instant firstEventTime, Instant triggerTime,
                 List<String> eventIds, Map<String, Object> evidence,
                 AlertStatus status, List<AlertTransition> history) {
        this.alertId = alertId;
        this.ruleId = ruleId;
        this.ruleVersion = ruleVersion;
        this.correlationKey = correlationKey;
        this.severity = severity;
        this.title = title;
        this.firstEventTime = firstEventTime;
        this.triggerTime = triggerTime;
        if (eventIds != null) {
            this.eventIds.addAll(eventIds);
        }
        if (evidence != null) {
            this.evidence.putAll(evidence);
        }
        this.status = status;
        if (history != null) {
            this.history.addAll(history);
        }
    }

    public String alertId() {
        return alertId;
    }

    public String ruleId() {
        return ruleId;
    }

    public String ruleVersion() {
        return ruleVersion;
    }

    public String correlationKey() {
        return correlationKey;
    }

    public Severity severity() {
        return severity;
    }

    public String title() {
        return title;
    }

    public Instant firstEventTime() {
        return firstEventTime;
    }

    public Instant triggerTime() {
        return triggerTime;
    }

    public List<String> eventIds() {
        return Collections.unmodifiableList(eventIds);
    }

    public Map<String, Object> evidence() {
        return Collections.unmodifiableMap(evidence);
    }

    public AlertStatus status() {
        return status;
    }

    public String mergedInto() {
        return mergedInto;
    }

    public List<AlertTransition> history() {
        return Collections.unmodifiableList(history);
    }

    /** 追加事件链中尚未包含的事件 ID，返回新加入的数量。 */
    public int appendEventIds(List<String> ids) {
        int added = 0;
        for (String id : ids) {
            if (!eventIds.contains(id)) {
                eventIds.add(id);
                added++;
            }
        }
        return added;
    }

    public void putEvidence(String key, Object value) {
        evidence.put(key, value);
    }

    public void setMergedInto(String mergedInto) {
        this.mergedInto = mergedInto;
    }

    public void setStatus(AlertStatus status) {
        this.status = status;
    }

    public void addTransition(AlertTransition transition) {
        history.add(transition);
    }
}
