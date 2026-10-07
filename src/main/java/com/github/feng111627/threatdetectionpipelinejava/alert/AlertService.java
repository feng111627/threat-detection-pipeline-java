package com.github.feng111627.threatdetectionpipelinejava.alert;

/**
 * 告警状态流转服务：校验流转合法性并落审计历史，非法流转抛错。
 */
public class AlertService {

    private final AlertStore store;

    public AlertService(AlertStore store) {
        this.store = store;
    }

    public void transition(String alertId, AlertStatus next, String reason) {
        Alert alert = store.findById(alertId)
                .orElseThrow(() -> new IllegalArgumentException("告警不存在: " + alertId));
        alert.transition(next, reason);
    }
}
