package com.github.feng111627.threatdetectionpipelinejava.model;

/**
 * 一条被拒绝的原始记录及其可区分的拒绝原因，绝不静默丢弃。
 */
public record RejectionRecord(
        String source,
        String rawLine,
        RejectStage stage,
        String reason) {
}
