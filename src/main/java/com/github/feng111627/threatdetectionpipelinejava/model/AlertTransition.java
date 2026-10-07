package com.github.feng111627.threatdetectionpipelinejava.model;

import java.time.Instant;

/**
 * 告警状态流转记录（可追溯）。
 */
public record AlertTransition(Instant at, AlertStatus from, AlertStatus to, String operator, String reason) {
}
