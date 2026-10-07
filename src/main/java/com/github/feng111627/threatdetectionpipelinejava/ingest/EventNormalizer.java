package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectedRecord;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 事件接入与归一化：编排 解析 -> 业务校验 -> 去重，任何记录都不允许静默丢弃。
 *
 * <p>拒绝原因分两大类（见 {@link com.github.feng111627.threatdetectionpipelinejava.model.RejectionCategory}）：
 * <ul>
 *   <li>PARSE：报文层面无法解析（空报文、格式非法、时间戳缺失/格式非法等）</li>
 *   <li>VALIDATION：报文可解析但业务校验不通过（字段缺失、类型未知、时间戳越界、重复等）</li>
 * </ul>
 */
@Component
public class EventNormalizer {

    private static final DateTimeFormatter SPACE_DATE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Map<String, SourceAdapter> adapters;
    private final DedupCache dedupCache;
    private final Clock clock;

    private final Set<String> allowedEventTypes;
    private final Duration maxFutureSkew;
    private final Duration maxAge;

    public EventNormalizer(List<SourceAdapter> adapters,
                           DedupCache dedupCache,
                           Clock clock,
                           @Value("${threat.allowed-event-types:LOGIN_SUCCESS,LOGIN_FAIL,PRIVILEGE_ESCALATION,"
                                   + "MALWARE_DETECTED,FIREWALL_BLOCK,SQLI_ATTEMPT,DATA_EXPORT,PROCESS_SPAWN}")
                           String allowedEventTypes,
                           @Value("${threat.max-future-skew-seconds:60}") long maxFutureSkewSeconds,
                           @Value("${threat.max-age-days:3650}") long maxAgeDays) {
        this.adapters = adapters.stream().collect(Collectors.toMap(SourceAdapter::sourceName, a -> a));
        this.dedupCache = dedupCache;
        this.clock = clock;
        this.allowedEventTypes = ArraysCompat.setOf(allowedEventTypes);
        this.maxFutureSkew = Duration.ofSeconds(maxFutureSkewSeconds);
        this.maxAge = Duration.ofDays(maxAgeDays);
    }

    public IngestResult ingest(List<RawEvent> rawEvents) {
        IngestResult result = new IngestResult();
        if (rawEvents == null) {
            return result;
        }
        for (RawEvent raw : rawEvents) {
            try {
                NormalizedEvent event = normalizeOne(raw);
                result.accepted().add(event);
            } catch (EventParseException e) {
                reject(raw, result, e.reason(), e.getMessage());
            } catch (EventValidationException e) {
                reject(raw, result, e.reason(), e.getMessage());
            }
        }
        return result;
    }

    private void reject(RawEvent raw, IngestResult result, RejectionReason reason, String detail) {
        result.rejected().add(new RejectedRecord(raw, reason, detail, Instant.now(clock)));
    }

    /** 清空事件去重记录（用于测试/场景隔离）。 */
    public void clearDedup() {
        dedupCache.clear();
    }

    private NormalizedEvent normalizeOne(RawEvent raw)
            throws EventParseException, EventValidationException {
        // 1. 来源路由
        String source = raw.source();
        if (source == null || source.isBlank()) {
            throw new EventValidationException(RejectionReason.MISSING_SOURCE, "source 为空");
        }
        SourceAdapter adapter = adapters.get(source);
        if (adapter == null) {
            throw new EventParseException(RejectionReason.UNSUPPORTED_FORMAT, "未知来源: " + source);
        }

        // 2. 报文解析（PARSE 类失败）
        ParsedEvent parsed = adapter.parse(raw);

        // 3. 时间戳：缺失与格式非法属于 PARSE；时间越界属于 VALIDATION
        if (parsed.rawTimestamp() == null || parsed.rawTimestamp().isBlank()) {
            throw new EventParseException(RejectionReason.MISSING_TIMESTAMP, "ts 字段缺失");
        }
        Instant eventTime = parseTimestamp(parsed.rawTimestamp());
        Instant now = Instant.now(clock);
        if (eventTime.isAfter(now.plus(maxFutureSkew))) {
            throw new EventValidationException(RejectionReason.TIMESTAMP_IN_FUTURE,
                    "事件时间 " + eventTime + " 超出允许偏移 " + maxFutureSkew);
        }
        if (eventTime.isBefore(now.minus(maxAge))) {
            throw new EventValidationException(RejectionReason.TIMESTAMP_TOO_OLD,
                    "事件时间 " + eventTime + " 早于允许的最早时间 " + now.minus(maxAge));
        }

        // 4. 业务字段校验（VALIDATION 类失败）
        if (parsed.eventType() == null || parsed.eventType().isBlank()) {
            throw new EventValidationException(RejectionReason.MISSING_EVENT_TYPE, "type 字段缺失");
        }
        if (!allowedEventTypes.contains(parsed.eventType())) {
            throw new EventValidationException(RejectionReason.UNKNOWN_EVENT_TYPE,
                    "未知事件类型: " + parsed.eventType());
        }
        boolean hasSubject = (parsed.sourceIp() != null && !parsed.sourceIp().isBlank())
                || (parsed.user() != null && !parsed.user().isBlank());
        if (!hasSubject) {
            throw new EventValidationException(RejectionReason.MISSING_SUBJECT,
                    "src_ip 与 user 不能同时为空");
        }

        // 5. 去重：同来源 + 来源记录 ID（无 ID 时退化为报文指纹）只放行一次
        if (!dedupCache.registerIfAbsent(source, parsed.sourceRecordId(), raw.rawPayload())) {
            throw new EventValidationException(RejectionReason.DUPLICATE_EVENT,
                    "source=" + source + ", recordId=" + parsed.sourceRecordId());
        }

        String stableId = parsed.sourceRecordId() != null && !parsed.sourceRecordId().isBlank()
                ? source + ":" + parsed.sourceRecordId()
                : source + ":" + fingerprint(raw.rawPayload());

        return new NormalizedEvent(
                stableId,
                source,
                parsed.sourceRecordId(),
                parsed.eventType(),
                blankToNull(parsed.sourceIp()),
                blankToNull(parsed.targetIp()),
                blankToNull(parsed.user()),
                eventTime,
                raw.receivedAt() != null ? raw.receivedAt() : now,
                parsed.attributes() == null ? Map.of() : parsed.attributes());
    }

    private static Instant parseTimestamp(String raw) throws EventParseException {
        String value = raw.trim();
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
            // 继续尝试其他格式
        }
        try {
            return LocalDateTime.parse(value, SPACE_DATE_TIME).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException ignored) {
            // 继续尝试其他格式
        }
        try {
            long epochMillis = Long.parseLong(value);
            return Instant.ofEpochMilli(epochMillis);
        } catch (NumberFormatException e) {
            throw new EventParseException(RejectionReason.MALFORMED_TIMESTAMP, "无法解析时间戳: " + raw);
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static String fingerprint(String payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-1 不可用", e);
        }
    }

    /** 内部小工具：避免文件顶部额外 import 数组工具。 */
    private static final class ArraysCompat {
        static Set<String> setOf(String csv) {
            return csv == null || csv.isBlank()
                    ? Set.of()
                    : java.util.Arrays.stream(csv.split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .collect(Collectors.toUnmodifiableSet());
        }
    }
}
