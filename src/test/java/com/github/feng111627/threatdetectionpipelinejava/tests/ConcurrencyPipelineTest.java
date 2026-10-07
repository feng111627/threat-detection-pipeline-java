package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.alert.Alert;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStatus;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStore;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventValidator;
import com.github.feng111627.threatdetectionpipelinejava.ingest.IngestionService;
import com.github.feng111627.threatdetectionpipelinejava.ingest.RawRecord;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.DetectionPipeline;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.PipelineConfig;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleEngine;
import com.github.feng111627.threatdetectionpipelinejava.simulation.LocalEventGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务场景：并发接入下告警数量与状态一致，重复消费不重复产出告警。
 */
class ConcurrencyPipelineTest {

    private static final Instant BASE = Instant.parse("2026-10-07T08:00:00Z");

    private DetectionPipeline newPipeline(AlertStore store, RuleEngine engine) {
        PipelineConfig config = new PipelineConfig();
        EventValidator validator = new EventValidator(
                Clock.fixed(BASE.plus(Duration.ofHours(2)), ZoneOffset.UTC),
                Duration.ofMinutes(5), Duration.ofDays(30));
        IngestionService ingestion = new IngestionService(config.eventParsers(), validator);
        return new DetectionPipeline(ingestion, engine, store);
    }

    @Test
    @DisplayName("并发接入：多线程提交同一批事件，告警数量确定且事件链完整合并")
    void concurrentIngestionKeepsAlertCountConsistent() throws InterruptedException {
        AlertStore store = new AlertStore();
        RuleEngine engine = new RuleEngine();
        engine.loadRules(PipelineConfig.defaultRules());
        DetectionPipeline pipeline = newPipeline(store, engine);

        // 同一用户 5 条登录失败（同一窗口）-> 频率规则只应产出 1 条告警
        LocalEventGenerator gen = new LocalEventGenerator(7, BASE);
        List<RawRecord> batch = List.of(
                gen.authLog("alice", 1), gen.authLog("alice", 2), gen.authLog("alice", 3),
                gen.authLog("alice", 4), gen.authLog("alice", 5));

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (RawRecord r : batch) {
                        var result = pipeline.submit(r);
                        if (result.status() == com.github.feng111627.threatdetectionpipelinejava
                                .ingest.IngestResult.Status.ACCEPTED) {
                            accepted.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // 8 个线程重复提交同一批：接受数必须等于批大小（幂等），告警必须只有 1 条
        assertEquals(batch.size(), accepted.get());
        assertEquals(1, store.count());
        Alert alert = store.findAll().get(0);
        // 告警事件链 = 构成命中的窗口事件（阈值 3，故为 3 条），语义确定
        assertEquals(3, alert.eventIds().size());
        assertEquals(AlertStatus.NEW, alert.status());
        TestLog.pass("并发接入一致性", "8线程重复提交同批事件仅产出1条告警且事件链完整");
    }

    @Test
    @DisplayName("并发命中：多线程同时触发同链命中，合并为一条告警且命中次数可追溯")
    void concurrentHitsMergeIntoOneAlert() throws InterruptedException {
        AlertStore store = new AlertStore();
        RuleEngine engine = new RuleEngine();
        engine.loadRules(PipelineConfig.defaultRules());
        DetectionPipeline pipeline = newPipeline(store, engine);

        // 两个用户各 3 条失败登录，交错并发提交 -> 每个用户一条告警
        LocalEventGenerator gen = new LocalEventGenerator(11, BASE);
        List<RawRecord> aliceEvents = List.of(
                gen.authLog("alice", 101), gen.authLog("alice", 102), gen.authLog("alice", 103));
        List<RawRecord> bobEvents = List.of(
                gen.authLog("bob", 201), gen.authLog("bob", 202), gen.authLog("bob", 203));

        ExecutorService pool = Executors.newFixedThreadPool(2);
        pool.submit(() -> aliceEvents.forEach(pipeline::submit));
        pool.submit(() -> bobEvents.forEach(pipeline::submit));
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        assertEquals(2, store.count());
        assertTrue(store.findAll().stream().allMatch(a -> a.eventIds().size() == 3));
        assertTrue(store.findAll().stream().allMatch(a -> a.hitCount() == 1));
        TestLog.pass("并发接入一致性", "并发命中按事件链各合并为一条告警");
    }

    @Test
    @DisplayName("重复消费：整批数据重放后告警数量不变")
    void replayDoesNotDuplicateAlerts() {
        AlertStore store = new AlertStore();
        RuleEngine engine = new RuleEngine();
        engine.loadRules(PipelineConfig.defaultRules());
        DetectionPipeline pipeline = newPipeline(store, engine);

        LocalEventGenerator gen = new LocalEventGenerator(13, BASE);
        List<RawRecord> batch = gen.shuffled(List.of(
                gen.authLog("carol", 301), gen.authLog("carol", 302), gen.authLog("carol", 303)));

        batch.forEach(pipeline::submit);
        long afterFirst = store.count();
        batch.forEach(pipeline::submit); // 整批重放
        batch.forEach(pipeline::submit); // 再次重放

        assertEquals(1, afterFirst);
        assertEquals(1, store.count());
        assertEquals(1, store.findAll().get(0).hitCount());
        TestLog.pass("并发接入一致性", "整批重复消费不重复产出告警");
    }
}
