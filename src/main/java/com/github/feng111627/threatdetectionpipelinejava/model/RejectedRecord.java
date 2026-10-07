package com.github.feng111627.threatdetectionpipelinejava.model;

import java.time.Instant;

/**
 * 被拒绝的记录及其可区分原因（不允许静默丢弃任何记录）。
 */
public record RejectedRecord(RawEvent rawEvent, RejectionReason reason, String detail, Instant rejectedAt) {
}
