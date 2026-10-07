package com.github.feng111627.threatdetectionpipelinejava.model;

import java.time.Instant;

/**
 * 原始安全事件：接入层收到的未经处理的记录。
 *
 * @param source         来源标识（firewall / edr / iam ...）
 * @param sourceRecordId 来源侧记录 ID（可能缺失）
 * @param rawPayload     原始报文
 * @param receivedAt     本地接入时间
 */
public record RawEvent(String source, String sourceRecordId, String rawPayload, Instant receivedAt) {
}
