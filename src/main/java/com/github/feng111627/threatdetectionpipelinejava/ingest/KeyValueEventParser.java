package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 通用的 key=value 格式解析器：各来源共用一套词法，字段名映射与类型映射按来源配置。
 * 解析失败（格式非法 / 字段缺失 / 时间戳异常 / 未知类型）统一抛出 ParseException。
 */
public class KeyValueEventParser implements EventParser {

    /**
     * 来源字段映射：标准字段 -> 该来源原始字段名。
     */
    public record FieldMapping(String idField, String tsField, String typeField,
                               String hostField, String userField,
                               Map<String, EventType> typeAliases) {
    }

    private final EventSource source;
    private final FieldMapping mapping;

    public KeyValueEventParser(EventSource source, FieldMapping mapping) {
        this.source = source;
        this.mapping = mapping;
    }

    @Override
    public EventSource supports() {
        return source;
    }

    @Override
    public SecurityEvent parse(RawRecord record) throws ParseException {
        String line = record.line();
        if (line == null || line.isBlank()) {
            throw new ParseException("格式非法: 记录为空");
        }
        Map<String, String> kv = tokenize(line);

        String id = required(kv, mapping.idField(), "事件ID");
        String tsRaw = required(kv, mapping.tsField(), "时间戳");
        String typeRaw = required(kv, mapping.typeField(), "事件类型");
        String host = required(kv, mapping.hostField(), "主机");

        Instant ts = parseTimestamp(tsRaw);
        EventType type = mapping.typeAliases().get(typeRaw);
        if (type == null) {
            throw new ParseException("未知事件类型: " + typeRaw);
        }
        String user = kv.get(mapping.userField());

        Map<String, String> attrs = new LinkedHashMap<>(kv);
        return new SecurityEvent(id, source.name(), type, ts, host, user, attrs);
    }

    private Map<String, String> tokenize(String line) throws ParseException {
        Map<String, String> kv = new HashMap<>();
        for (String token : line.trim().split("\\s+")) {
            int eq = token.indexOf('=');
            if (eq <= 0 || eq == token.length() - 1) {
                throw new ParseException("格式非法: 无法解析的片段 [" + token + "]");
            }
            kv.put(token.substring(0, eq), token.substring(eq + 1));
        }
        return kv;
    }

    private String required(Map<String, String> kv, String field, String label) throws ParseException {
        String v = kv.get(field);
        if (v == null || v.isBlank()) {
            throw new ParseException("字段缺失: " + label + "(" + field + ")");
        }
        return v;
    }

    private Instant parseTimestamp(String raw) throws ParseException {
        try {
            if (raw.matches("\\d+")) {
                return Instant.ofEpochMilli(Long.parseLong(raw));
            }
            return Instant.parse(raw);
        } catch (DateTimeParseException | NumberFormatException | ArithmeticException e) {
            throw new ParseException("时间戳异常: " + raw);
        }
    }
}
