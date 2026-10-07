package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * iam 来源适配器：报文为分号分隔的键值对，例如
 * event_id=ev-1;type=LOGIN_FAIL;ts=2026-10-07T10:00:00Z;user=alice;src_ip=10.0.0.1
 * 无法解析的片段 -> MALFORMED_KEYVALUE；标准字段之外的键进入 attributes。
 */
public class KeyValueSourceAdapter implements SourceAdapter {

    public static final String SOURCE = "iam";

    private static final Set<String> STANDARD_KEYS =
            Set.of("event_id", "type", "ts", "src_ip", "dst_ip", "user");

    @Override
    public String sourceName() {
        return SOURCE;
    }

    @Override
    public ParsedEvent parse(RawEvent raw) throws EventParseException {
        String payload = raw.rawPayload();
        if (payload == null || payload.isBlank()) {
            throw new EventParseException(RejectionReason.EMPTY_PAYLOAD, "iam 报文为空");
        }

        Map<String, String> all = new LinkedHashMap<>();
        String[] segments = payload.strip().split(";", -1);
        for (String segment : segments) {
            if (segment.isBlank()) {
                throw new EventParseException(RejectionReason.MALFORMED_KEYVALUE, "存在空片段");
            }
            int eq = segment.indexOf('=');
            if (eq <= 0) {
                throw new EventParseException(RejectionReason.MALFORMED_KEYVALUE, "无法解析的片段: " + segment);
            }
            String key = segment.substring(0, eq).trim();
            String value = segment.substring(eq + 1).trim();
            if (key.isEmpty()) {
                throw new EventParseException(RejectionReason.MALFORMED_KEYVALUE, "存在空键");
            }
            all.merge(key, value.isEmpty() ? null : value, (a, b) -> b);
        }

        Map<String, String> attributes = new LinkedHashMap<>();
        all.forEach((key, value) -> {
            if (!STANDARD_KEYS.contains(key)) {
                attributes.put(key, value);
            }
        });

        return new ParsedEvent(
                raw.source(),
                all.get("event_id"),
                all.get("type"),
                all.get("src_ip"),
                all.get("dst_ip"),
                all.get("user"),
                all.get("ts"),
                attributes);
    }
}
