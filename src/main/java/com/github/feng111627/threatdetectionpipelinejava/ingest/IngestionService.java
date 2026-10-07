package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RejectStage;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionRecord;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 接入服务：解析 -> 业务校验 -> 幂等去重。
 * 任何失败都产出带阶段与原因的拒绝记录，绝不静默丢弃；
 * 已见过的 eventId 重复到达时返回 DUPLICATE，保证重复消费不重复进入检测链路。
 */
public class IngestionService {

    private final Map<EventSource, EventParser> parsers;
    private final EventValidator validator;
    private final Set<String> seenEventIds = ConcurrentHashMap.newKeySet();
    private final List<RejectionRecord> rejections = new CopyOnWriteArrayList<>();

    public IngestionService(List<EventParser> parsers, EventValidator validator) {
        this.parsers = parsers.stream()
                .collect(Collectors.toMap(EventParser::supports, Function.identity()));
        this.validator = validator;
    }

    public IngestResult ingest(RawRecord record) {
        String sourceName = record.source() == null ? "UNKNOWN" : record.source().name();

        EventParser parser = record.source() == null ? null : parsers.get(record.source());
        if (parser == null) {
            return reject(sourceName, record.line(), RejectStage.PARSE,
                    "不支持的来源: " + sourceName);
        }

        SecurityEvent event;
        try {
            event = parser.parse(record);
        } catch (ParseException e) {
            return reject(sourceName, record.line(), RejectStage.PARSE, e.getMessage());
        }

        try {
            validator.validate(event);
        } catch (ValidationException e) {
            return reject(sourceName, record.line(), RejectStage.VALIDATE, e.getMessage());
        }

        if (!seenEventIds.add(event.eventId())) {
            return IngestResult.duplicate(event);
        }
        return IngestResult.accepted(event);
    }

    private IngestResult reject(String source, String line, RejectStage stage, String reason) {
        RejectionRecord rejection = new RejectionRecord(source, line, stage, reason);
        rejections.add(rejection);
        return IngestResult.rejected(rejection);
    }

    public List<RejectionRecord> rejections() {
        return List.copyOf(rejections);
    }
}
