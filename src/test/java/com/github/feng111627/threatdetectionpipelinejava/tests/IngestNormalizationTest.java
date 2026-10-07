package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.ingest.CsvSourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.ingest.DedupCache;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventNormalizer;
import com.github.feng111627.threatdetectionpipelinejava.ingest.JsonSourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.ingest.KeyValueSourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.ingest.SourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.model.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectedRecord;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionCategory;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域一：多来源事件接入与归一化。
 */
class IngestNormalizationTest extends BusinessTestBase {

    private EventNormalizer normalizer;
    private DedupCache dedupCache;

    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");

    @BeforeAll
    static void header() {
        System.out.println("========== 业务域一：多来源接入与归一化 ==========");
    }

    @BeforeEach
    void setUp() {
        dedupCache = new DedupCache();
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        List<SourceAdapter> adapters = List.of(
                new JsonSourceAdapter(), new CsvSourceAdapter(), new KeyValueSourceAdapter());
        normalizer = new EventNormalizer(adapters, dedupCache, clock,
                "LOGIN_SUCCESS,LOGIN_FAIL,PRIVILEGE_ESCALATION,MALWARE_DETECTED,FIREWALL_BLOCK,DATA_EXPORT,PROCESS_SPAWN,SQLI_ATTEMPT",
                60, 3650);
    }

    private RawEvent raw(String source, String id, String payload) {
        return new RawEvent(source, id, payload, NOW);
    }

    private RejectedRecord onlyRejection(String source, String id, String payload) {
        IngestResult result = normalizer.ingest(List.of(raw(source, id, payload)));
        assertEquals(1, result.rejected().size(), "应恰好拒绝 1 条");
        assertEquals(0, result.accepted().size(), "不应有接入成功的记录");
        return result.rejected().get(0);
    }

    @Test
    @DisplayName("用例1.1 三种来源(JSON/CSV/键值对)都能归一化为统一事件")
    void multiSourceNormalize() {
        List<RawEvent> batch = List.of(
                raw("firewall", "f1", "{\"event_id\":\"f1\",\"type\":\"FIREWALL_BLOCK\","
                        + "\"ts\":\"2026-10-07T11:59:00Z\",\"src_ip\":\"1.1.1.1\"}"),
                raw("edr", "e1", "e1,MALWARE_DETECTED,2026-10-07 11:59:10,2.2.2.2,,host,HIGH"),
                raw("iam", "i1", "event_id=i1;type=LOGIN_FAIL;ts=2026-10-07T11:59:20Z;user=alice;src_ip=3.3.3.3"));
        IngestResult result = normalizer.ingest(batch);
        assertEquals(3, result.accepted().size());
        assertEquals("firewall", result.accepted().get(0).source());
        assertEquals("MALWARE_DETECTED", result.accepted().get(1).eventType());
        assertEquals("alice", result.accepted().get(2).user());
        assertEquals("3.3.3.3", result.accepted().get(2).sourceIp());
    }

    @Test
    @DisplayName("用例1.2 支持多种时间戳格式：ISO/空格格式/epochMillis")
    void timestampFormats() {
        List<RawEvent> batch = List.of(
                raw("firewall", "t1", "{\"event_id\":\"t1\",\"type\":\"FIREWALL_BLOCK\","
                        + "\"ts\":\"2026-10-07T11:00:00Z\",\"src_ip\":\"1.1.1.1\"}"),
                raw("edr", "t2", "t2,PROCESS_SPAWN,2026-10-07 11:00:05,1.1.1.1,,,LOW"),
                raw("edr", "t3", "t3,PROCESS_SPAWN,1759834810000,1.1.1.1,,,LOW"));
        IngestResult result = normalizer.ingest(batch);
        assertEquals(3, result.accepted().size(), () -> result.rejected().toString());
        assertEquals(Instant.parse("2026-10-07T11:00:00Z"), result.accepted().get(0).eventTime());
        assertEquals(Instant.ofEpochMilli(1759834810000L), result.accepted().get(2).eventTime());
    }

    @Test
    @DisplayName("用例1.3 JSON 非法归类为 PARSE/P003，而非业务校验")
    void malformedJsonIsParseError() {
        RejectedRecord r = onlyRejection("firewall", "bad", "{oops");
        assertEquals(RejectionCategory.PARSE, r.reason().category());
        assertEquals(RejectionReason.MALFORMED_JSON, r.reason());
    }

    @Test
    @DisplayName("用例1.4 CSV 列数非法归类为 PARSE/P004")
    void malformedCsvIsParseError() {
        RejectedRecord r = onlyRejection("edr", "bad", "a,b,c");
        assertEquals(RejectionCategory.PARSE, r.reason().category());
        assertEquals(RejectionReason.MALFORMED_CSV, r.reason());
    }

    @Test
    @DisplayName("用例1.5 键值对片段非法归类为 PARSE/P005")
    void malformedKvIsParseError() {
        RejectedRecord r = onlyRejection("iam", "bad", "event_id=bad;nonsense");
        assertEquals(RejectionCategory.PARSE, r.reason().category());
        assertEquals(RejectionReason.MALFORMED_KEYVALUE, r.reason());
    }

    @Test
    @DisplayName("用例1.6 缺少时间戳归类为 PARSE/P006，时间戳格式非法归类为 PARSE/P007")
    void missingAndMalformedTimestamp() {
        RejectedRecord missing = onlyRejection("firewall", "m",
                "{\"event_id\":\"m\",\"type\":\"FIREWALL_BLOCK\",\"src_ip\":\"1.1.1.1\"}");
        assertEquals(RejectionReason.MISSING_TIMESTAMP, missing.reason());
        RejectedRecord bad = onlyRejection("firewall", "b",
                "{\"event_id\":\"b\",\"type\":\"FIREWALL_BLOCK\",\"ts\":\"not-a-time\",\"src_ip\":\"1.1.1.1\"}");
        assertEquals(RejectionReason.MALFORMED_TIMESTAMP, bad.reason());
    }

    @Test
    @DisplayName("用例1.7 缺少事件类型/主体归类为 VALIDATION，与 PARSE 明确区分")
    void fieldMissingIsValidationError() {
        RejectedRecord noType = onlyRejection("firewall", "v1",
                "{\"event_id\":\"v1\",\"ts\":\"2026-10-07T11:59:00Z\",\"src_ip\":\"1.1.1.1\"}");
        assertEquals(RejectionCategory.VALIDATION, noType.reason().category());
        assertEquals(RejectionReason.MISSING_EVENT_TYPE, noType.reason());

        RejectedRecord noSubject = onlyRejection("firewall", "v2",
                "{\"event_id\":\"v2\",\"type\":\"FIREWALL_BLOCK\",\"ts\":\"2026-10-07T11:59:00Z\"}");
        assertEquals(RejectionReason.MISSING_SUBJECT, noSubject.reason());
    }

    @Test
    @DisplayName("用例1.8 时间戳在未来/过早归类为 VALIDATION（V005/V006）")
    void timestampOutOfRangeIsValidationError() {
        RejectedRecord future = onlyRejection("firewall", "f",
                "{\"event_id\":\"f\",\"type\":\"FIREWALL_BLOCK\",\"ts\":\"2099-01-01T00:00:00Z\",\"src_ip\":\"1.1.1.1\"}");
        assertEquals(RejectionReason.TIMESTAMP_IN_FUTURE, future.reason());

        RejectedRecord old = onlyRejection("firewall", "o",
                "{\"event_id\":\"o\",\"type\":\"FIREWALL_BLOCK\",\"ts\":\"2000-01-01T00:00:00Z\",\"src_ip\":\"1.1.1.1\"}");
        assertEquals(RejectionReason.TIMESTAMP_TOO_OLD, old.reason());
    }

    @Test
    @DisplayName("用例1.9 未知来源/空报文分别给出 P002/P001，不静默丢弃")
    void unknownSourceAndEmptyPayload() {
        RejectedRecord unknown = onlyRejection("ids-probe", "x", "anything");
        assertEquals(RejectionReason.UNSUPPORTED_FORMAT, unknown.reason());
        RejectedRecord empty = onlyRejection("edr", "z", "   ");
        assertEquals(RejectionReason.EMPTY_PAYLOAD, empty.reason());
    }

    @Test
    @DisplayName("用例1.10 缺失来源归类为 VALIDATION/V001")
    void missingSource() {
        RejectedRecord r = onlyRejection(null, "n", "event_id=n;type=LOGIN_FAIL;ts=2026-10-07T11:59:00Z;user=a");
        assertEquals(RejectionReason.MISSING_SOURCE, r.reason());
    }

    @Test
    @DisplayName("用例1.11 重复记录第二次归类为 VALIDATION/V007 且只放行一次")
    void duplicateRejectedOnce() {
        RawEvent event = raw("iam", "dup",
                "event_id=dup;type=LOGIN_FAIL;ts=2026-10-07T11:59:00Z;user=a;src_ip=1.1.1.1");
        IngestResult first = normalizer.ingest(List.of(event));
        assertEquals(1, first.accepted().size());
        IngestResult second = normalizer.ingest(List.of(event));
        assertEquals(0, second.accepted().size());
        assertEquals(RejectionReason.DUPLICATE_EVENT, second.rejected().get(0).reason());
    }

    @Test
    @DisplayName("用例1.12 任何记录都不静默丢弃：接受数+拒绝数=输入数")
    void noSilentDrop() {
        List<RawEvent> batch = List.of(
                raw("firewall", "ok1", "{\"event_id\":\"ok1\",\"type\":\"FIREWALL_BLOCK\","
                        + "\"ts\":\"2026-10-07T11:59:00Z\",\"src_ip\":\"1.1.1.1\"}"),
                raw("firewall", "bad1", "{oops"),
                raw("edr", "bad2", "only,two,cols"),
                raw("iam", "ok2", "event_id=ok2;type=LOGIN_FAIL;ts=2026-10-07T11:59:00Z;user=a;src_ip=2.2.2.2"));
        IngestResult result = normalizer.ingest(batch);
        assertEquals(batch.size(), result.accepted().size() + result.rejected().size());
        assertTrue(result.accepted().size() >= 2);
    }
}
