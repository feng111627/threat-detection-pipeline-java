package com.github.feng111627.threatdetectionpipelinejava.alert;

import com.github.feng111627.threatdetectionpipelinejava.model.AlertStatus;

/**
 * 非法的告警状态流转。
 */
public class IllegalAlertTransitionException extends RuntimeException {

    public IllegalAlertTransitionException(String alertId, AlertStatus from, AlertStatus to) {
        super("告警 " + alertId + " 不允许从 " + from + " 流转到 " + to);
    }
}
