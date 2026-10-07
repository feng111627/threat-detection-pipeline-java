package com.github.feng111627.threatdetectionpipelinejava.model;

import java.time.Instant;
import java.util.Map;

/**
 * 归一化后的安全事件，所有来源的日志最终都转成该结构进入检测链路。
 */
public record SecurityEvent(
        String eventId,
        String source,
        EventType type,
        Instant timestamp,
        String host,
        String user,
        Map<String, String> attributes) {
}
