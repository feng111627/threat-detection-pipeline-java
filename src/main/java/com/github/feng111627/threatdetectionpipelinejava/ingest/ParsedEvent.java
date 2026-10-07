package com.github.feng111627.threatdetectionpipelinejava.ingest;

import java.time.Instant;
import java.util.Map;

/**
 * 报文解析结果（尚未做业务校验的中间形态）。
 * 时间戳先保留为字符串，由归一化阶段统一解析，便于区分「格式非法」与「业务不合法」。
 */
public record ParsedEvent(
        String source,
        String sourceRecordId,
        String eventType,
        String sourceIp,
        String targetIp,
        String user,
        String rawTimestamp,
        Map<String, String> attributes) {
}
