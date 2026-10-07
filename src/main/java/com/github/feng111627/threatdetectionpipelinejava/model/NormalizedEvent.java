package com.github.feng111627.threatdetectionpipelinejava.model;

import java.time.Instant;
import java.util.Map;

/**
 * 归一化后的安全事件，检测层只消费该类型。
 */
public record NormalizedEvent(
        String eventId,
        String source,
        String sourceRecordId,
        String eventType,
        String sourceIp,
        String targetIp,
        String user,
        Instant eventTime,
        Instant ingestTime,
        Map<String, String> attributes) {

    public NormalizedEvent {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
