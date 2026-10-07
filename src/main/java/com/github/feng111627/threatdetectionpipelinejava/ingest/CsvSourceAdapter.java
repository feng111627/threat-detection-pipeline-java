package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * edr 来源适配器：报文为单行 CSV，固定 7 列：
 * event_id,type,ts,src_ip,dst_ip,user,severity
 * 列数不符 -> MALFORMED_CSV；空字段按缺失处理（交给业务校验）。
 */
public class CsvSourceAdapter implements SourceAdapter {

    public static final String SOURCE = "edr";

    private static final int EXPECTED_COLUMNS = 7;

    @Override
    public String sourceName() {
        return SOURCE;
    }

    @Override
    public ParsedEvent parse(RawEvent raw) throws EventParseException {
        String payload = raw.rawPayload();
        if (payload == null || payload.isBlank()) {
            throw new EventParseException(RejectionReason.EMPTY_PAYLOAD, "edr 报文为空");
        }
        String line = payload.strip();
        if (line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0) {
            throw new EventParseException(RejectionReason.MALFORMED_CSV, "单条记录不允许包含换行");
        }
        String[] columns = line.split(",", -1);
        if (columns.length != EXPECTED_COLUMNS) {
            throw new EventParseException(RejectionReason.MALFORMED_CSV,
                    "期望 " + EXPECTED_COLUMNS + " 列，实际 " + columns.length + " 列");
        }

        Map<String, String> attributes = new LinkedHashMap<>();
        String severity = columns[6].isBlank() ? null : columns[6].trim();
        if (severity != null) {
            attributes.put("severity", severity);
        }

        return new ParsedEvent(
                raw.source(),
                blankToNull(columns[0]),
                blankToNull(columns[1]),
                blankToNull(columns[3]),
                blankToNull(columns[4]),
                blankToNull(columns[5]),
                blankToNull(columns[2]),
                attributes);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
