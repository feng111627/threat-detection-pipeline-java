package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * firewall 来源适配器：报文为单行 JSON。
 * 标准字段：event_id / type / ts / src_ip / dst_ip / user，其余字段进入 attributes。
 */
public class JsonSourceAdapter implements SourceAdapter {

    public static final String SOURCE = "firewall";

    private static final Set<String> STANDARD_KEYS =
            Set.of("event_id", "type", "ts", "src_ip", "dst_ip", "user");

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String sourceName() {
        return SOURCE;
    }

    @Override
    public ParsedEvent parse(RawEvent raw) throws EventParseException {
        String payload = raw.rawPayload();
        if (payload == null || payload.isBlank()) {
            throw new EventParseException(RejectionReason.EMPTY_PAYLOAD, "firewall 报文为空");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(payload);
        } catch (JsonProcessingException e) {
            throw new EventParseException(RejectionReason.MALFORMED_JSON, e.getOriginalMessage());
        }
        if (root == null || !root.isObject()) {
            throw new EventParseException(RejectionReason.MALFORMED_JSON, "根节点不是 JSON 对象");
        }

        Map<String, String> attributes = new LinkedHashMap<>();
        root.fields().forEachRemaining(entry -> {
            if (!STANDARD_KEYS.contains(entry.getKey())) {
                JsonNode value = entry.getValue();
                attributes.put(entry.getKey(), value == null || value.isNull() ? null : value.asText());
            }
        });

        return new ParsedEvent(
                raw.source(),
                textOrNull(root.get("event_id")),
                textOrNull(root.get("type")),
                textOrNull(root.get("src_ip")),
                textOrNull(root.get("dst_ip")),
                textOrNull(root.get("user")),
                textOrNull(root.get("ts")),
                attributes);
    }

    private static String textOrNull(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }
}
