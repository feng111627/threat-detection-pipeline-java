package com.github.feng111627.threatdetectionpipelinejava.alert;

import java.time.Instant;

/**
 * 一次状态变更的审计记录，保证状态可追溯。
 */
public record StatusChange(AlertStatus from, AlertStatus to, Instant at, String reason) {
}
