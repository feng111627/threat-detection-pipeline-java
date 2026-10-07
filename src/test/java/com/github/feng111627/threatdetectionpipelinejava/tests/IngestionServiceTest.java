package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.ingest.EventParser;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventSource;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventValidator;
import com.github.feng111627.threatdetectionpipelinejava.ingest.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.ingest.IngestionService;
import com.github.feng111627.threatdetectionpipelinejava.ingest.KeyValueEventParser;
import com.github.feng111627.threatdetectionpipelinejava.ingest.RawRecord;
import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectStage;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.PipelineConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务场景：多来源事件接入与归一化。
 * 验证解析失败与业务校验失败可分别定位，且任何记录都不被静默丢弃。
 */
class IngestionServiceTest {

    private static final Instant BASE = Instant.parse("2026-10-07T08:00:00Z");
    private IngestionService service;

    @BeforeEach
    void setUp() {
        List<EventParser> parsers = new PipelineConfig().eventParsers();
        EventValidator validator = new EventValidator(
                Clock.fixed(BASE.plus(Duration.ofHours(1)), ZoneOffset.UTC),
                Duration.ofMinutes(5), Duration.ofDays(30));
        service = new IngestionService(parsers, validator);
    }

    @Test
    @DisplayName("多来源合法记录均被归一化接入")
    void acceptsAllSources() {
        assertEquals(IngestResult.Status.ACCEPTED, service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0001 time=2026-10-07T08:30:00Z result=FAIL server=web1 account=alice")).status());
        assertEquals(IngestResult.Status.ACCEPTED, service.ingest(new RawRecord(EventSource.FIREWALL,
                "fid=f-0001 ts=2026-10-07T08:30:01Z action=SCAN device=fw1 ports=20")).status());
        assertEquals(IngestResult.Status.ACCEPTED, service.ingest(new RawRecord(EventSource.HOST_AGENT,
                "hid=h-0001 ts=2026-10-07T08:30:02Z op=EXEC node=n1 user=bob")).status());
        assertEquals(IngestResult.Status.ACCEPTED, service.ingest(new RawRecord(EventSource.IDS,
                "iid=i-0001 ts=2026-10-07T08:30:03Z sig=PORTSCAN sensor=ids1 user=carol")).status());
        assertEquals(0, service.rejections().size());
        TestLog.pass("多来源接入与归一化", "四种来源合法记录全部接受");
    }

    @Test
    @DisplayName("归一化结果字段映射正确")
    void normalizesFields() {
        IngestResult result = service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0002 time=2026-10-07T08:30:00Z result=FAIL server=web1 account=alice"));
        assertEquals(EventType.LOGIN_FAILED, result.event().type());
        assertEquals("alice", result.event().user());
        assertEquals("web1", result.event().host());
        assertEquals(Instant.parse("2026-10-07T08:30:00Z"), result.event().timestamp());
        TestLog.pass("多来源接入与归一化", "来源字段映射到统一模型");
    }

    @Test
    @DisplayName("解析失败可定位具体原因：格式非法/字段缺失/时间戳异常/未知类型")
    void parseFailuresAreDistinguishable() {
        IngestResult malformed = service.ingest(new RawRecord(EventSource.AUTH_LOG, "这不是键值对"));
        IngestResult missing = service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0003 result=FAIL server=web1 account=alice"));
        IngestResult badTs = service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0004 time=不是时间 result=FAIL server=web1 account=alice"));
        IngestResult unknownType = service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0005 time=2026-10-07T08:30:00Z result=UNKNOWN server=web1 account=alice"));

        assertEquals(RejectStage.PARSE, malformed.rejection().stage());
        assertTrue(malformed.rejection().reason().contains("格式非法"));
        assertTrue(missing.rejection().reason().contains("字段缺失"));
        assertTrue(badTs.rejection().reason().contains("时间戳异常"));
        assertTrue(unknownType.rejection().reason().contains("未知事件类型"));
        assertEquals(4, service.rejections().size());
        TestLog.pass("多来源接入与归一化", "四类解析失败原因可区分定位");
    }

    @Test
    @DisplayName("业务校验失败与解析失败分开定位")
    void validationFailuresAreSeparateFromParse() {
        IngestResult future = service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0006 time=2026-10-07T10:00:00Z result=FAIL server=web1 account=alice"));
        IngestResult noUser = service.ingest(new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0007 time=2026-10-07T08:30:00Z result=FAIL server=web1 account="));

        assertEquals(RejectStage.VALIDATE, future.rejection().stage());
        assertTrue(future.rejection().reason().contains("未来偏移"));
        // account= 空值在解析期即被判为格式非法，体现两阶段各自定位
        assertEquals(RejectStage.PARSE, noUser.rejection().stage());
        TestLog.pass("多来源接入与归一化", "业务校验失败与解析失败分阶段定位");
    }

    @Test
    @DisplayName("重复事件幂等：同一 eventId 不重复进入链路")
    void duplicatesAreIdempotent() {
        RawRecord record = new RawRecord(EventSource.AUTH_LOG,
                "aid=a-0008 time=2026-10-07T08:30:00Z result=FAIL server=web1 account=alice");
        assertEquals(IngestResult.Status.ACCEPTED, service.ingest(record).status());
        assertEquals(IngestResult.Status.DUPLICATE, service.ingest(record).status());
        assertEquals(0, service.rejections().size());
        TestLog.pass("多来源接入与归一化", "重复事件幂等去重");
    }
}
