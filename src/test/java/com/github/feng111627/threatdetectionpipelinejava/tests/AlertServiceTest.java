package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.alert.AlertService;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStore;
import com.github.feng111627.threatdetectionpipelinejava.alert.IllegalAlertTransitionException;
import com.github.feng111627.threatdetectionpipelinejava.engine.AlertSeed;
import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.AlertStatus;
import com.github.feng111627.threatdetectionpipelinejava.model.Severity;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域三：告警去重、事件链合并与合法状态流转（含并发一致性）。
 */
class AlertServiceTest extends BusinessTestBase {

    private static final Instant T0 = Instant.parse("2026-10-07T10:00:00Z");
    private AlertStore store;
    private AlertService service;

    @BeforeAll
    static void header() {
        System.out.println("========== 业务域三：告警去重/合并/状态流转 ==========");
    }

    @BeforeEach
    void setUp() {
        store = new AlertStore();
        service = new AlertService(store, Clock.fixed(T0, ZoneOffset.UTC));
    }

    private AlertSeed seed(String rule, String version, String correlationKey, List<String> eventIds) {
        return new AlertSeed(rule, version, correlationKey, Severity.HIGH, rule + " 命中",
                T0, T0, eventIds, Map.of("matchedCount", eventIds.size()));
    }

    @Test
    @DisplayName("用例3.1 相同 correlationKey 只落一条告警（幂等去重）")
    void idempotentByCorrelationKey() {
        AlertSeed seed = seed("R1", "v1", "R1|0|a", List.of("e1", "e2"));
        Alert first = service.ingestSeed(seed);
        Alert second = service.ingestSeed(seed);
        assertEquals(first.alertId(), second.alertId());
        assertEquals(1, service.allAlerts().size());
        assertEquals(AlertStatus.NEW, first.status());
        // 创建审计 1 条；第二次幂等命中再记 1 条可追溯自审计
        assertEquals(2, second.history().size());
        assertEquals(AlertStatus.NEW, second.history().get(0).to());
        assertTrue(second.history().get(1).reason().contains("重复消费"));
    }

    @Test
    @DisplayName("用例3.2 同事件链补充的事件被合并进同一告警，不新增告警数量")
    void sameChainEventsMergedIntoOne() {
        Alert a = service.ingestSeed(seed("R1", "v1", "R1|0|a", List.of("e1", "e2")));
        Alert b = service.ingestSeed(seed("R1", "v1", "R1|0|a", List.of("e2", "e3", "e4")));
        assertEquals(a.alertId(), b.alertId());
        assertEquals(1, service.allAlerts().size());
        assertTrue(b.eventIds().containsAll(List.of("e1", "e2", "e3", "e4")));
        assertEquals(4, b.eventIds().size(), "重复事件 e2 不应重复计入");
    }

    @Test
    @DisplayName("用例3.3 合法状态流转 NEW->ACK->RESOLVED->重开 全部记录审计")
    void legalTransitionsAudited() {
        Alert a = service.ingestSeed(seed("R1", "v1", "R1|0|a", List.of("e1")));
        service.acknowledge(a.alertId(), "analyst", "开始处置");
        service.resolve(a.alertId(), "analyst", "处置完成");
        service.reopen(a.alertId(), "analyst", "发现新证据，重开");
        Alert reloaded = store.findById(a.alertId()).orElseThrow();
        assertEquals(AlertStatus.ACKNOWLEDGED, reloaded.status());
        // 审计：创建 + 3 次流转
        assertEquals(4, reloaded.history().size());
        assertEquals(AlertStatus.NEW, reloaded.history().get(0).to());
        assertEquals(AlertStatus.ACKNOWLEDGED, reloaded.history().get(1).to());
        assertEquals(AlertStatus.RESOLVED, reloaded.history().get(2).to());
        assertEquals(AlertStatus.ACKNOWLEDGED, reloaded.history().get(3).to());
    }

    @Test
    @DisplayName("用例3.4 非法流转 NEW->MERGED 之外的跳跃（NEW 直接…）及 MERGED 终态被拒绝")
    void illegalTransitionsRejected() {
        Alert a = service.ingestSeed(seed("R1", "v1", "R1|0|a", List.of("e1")));
        // RESOLVED -> NEW 非法（只能重开到 ACKNOWLEDGED）
        service.acknowledge(a.alertId(), "op", null);
        service.resolve(a.alertId(), "op", null);
        assertThrows(IllegalAlertTransitionException.class,
                () -> service.transition(a.alertId(), AlertStatus.NEW, "op", "非法重开到 NEW"));
    }

    @Test
    @DisplayName("用例3.5 合并同规则告警：子告警进入 MERGED 终态，父告警吸收事件并记录追溯")
    void mergeSameRule() {
        Alert parent = service.ingestSeed(seed("R1", "v1", "R1|0|a", List.of("e1")));
        Alert child = service.ingestSeed(seed("R1", "v1", "R1|60|a", List.of("e2", "e3")));
        Alert mergedParent = service.merge(child.alertId(), parent.alertId(), "analyst");

        assertEquals(parent.alertId(), mergedParent.alertId());
        assertTrue(mergedParent.eventIds().containsAll(List.of("e1", "e2", "e3")));
        Alert childAfter = store.findById(child.alertId()).orElseThrow();
        assertEquals(AlertStatus.MERGED, childAfter.status());
        assertEquals(parent.alertId(), childAfter.mergedInto());
        // MERGED 是终态，不允许再流转
        assertThrows(IllegalAlertTransitionException.class,
                () -> service.acknowledge(child.alertId(), "op", null));
    }

    @Test
    @DisplayName("用例3.6 不同规则的告警不允许合并")
    void mergeDifferentRuleRejected() {
        Alert a = service.ingestSeed(seed("R1", "v1", "R1|0|a", List.of("e1")));
        Alert b = service.ingestSeed(seed("R2", "v1", "R2|0|a", List.of("e2")));
        assertThrows(IllegalArgumentException.class, () -> service.merge(b.alertId(), a.alertId(), "op"));
    }

    @Test
    @DisplayName("用例3.7 告警固化规则版本，便于规则调整后复现历史结论")
    void ruleVersionPinned() {
        Alert a = service.ingestSeed(seed("R1", "2026-10-07-v1", "R1|0|a", List.of("e1")));
        assertEquals("2026-10-07-v1", a.ruleVersion());
        Alert b = service.ingestSeed(seed("R1", "2026-10-07-v2", "R1|60|a", List.of("e2")));
        assertNotEquals(a.ruleVersion(), b.ruleVersion(), "不同窗口/版本各自固化");
    }

    @Test
    @DisplayName("用例3.8 并发接入同一事件链：最终恰好一条告警，事件链完整，计数一致")
    void concurrentSameChainConsistent() throws InterruptedException {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger errors = new AtomicInteger();
        String key = "R1|0|conc";
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    // 每个线程带一个独有事件，全部应被并入唯一告警
                    service.ingestSeed(seed("R1", "v1", key, List.of("evt-" + idx)));
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(0, errors.get());
        List<Alert> alerts = service.allAlerts();
        long sameKey = alerts.stream().filter(a -> a.correlationKey().equals(key)).count();
        assertEquals(1, sameKey, "同一事件链并发下必须只有一条告警");
        Alert only = alerts.stream().filter(a -> a.correlationKey().equals(key)).findFirst().orElseThrow();
        assertEquals(threads, only.eventIds().size(), "全部 " + threads + " 个事件都必须并入");
        assertEquals(AlertStatus.NEW, only.status());
    }

    @Test
    @DisplayName("用例3.9 并发接入不同事件链：数量与每条链归属保持一致")
    void concurrentDifferentChainsConsistent() throws InterruptedException {
        int chains = 50;
        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(chains);
        for (int i = 0; i < chains; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    service.ingestSeed(seed("R1", "v1", "R1|0|chain-" + idx, List.of("e" + idx)));
                    // 重复提交同一条链
                    service.ingestSeed(seed("R1", "v1", "R1|0|chain-" + idx, List.of("e" + idx)));
                } catch (Exception ignored) {
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(chains, service.allAlerts().size(), "每条链一条，重复不增加");
    }
}
