package com.github.feng111627.threatdetectionpipelinejava.tests;

import com.github.feng111627.threatdetectionpipelinejava.alert.Alert;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertService;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStatus;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStore;
import com.github.feng111627.threatdetectionpipelinejava.rule.AlertCandidate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 业务场景：告警去重合并与状态流转合法、可追溯。
 */
class AlertLifecycleTest {

    private AlertStore storeWithOneAlert() {
        AlertStore store = new AlertStore();
        store.upsert(new AlertCandidate("R1", 1, "R1|alice", List.of("e1", "e2", "e3"), "命中"));
        return store;
    }

    @Test
    @DisplayName("同链命中合并：去重键相同只保留一条告警")
    void sameChainMerges() {
        AlertStore store = storeWithOneAlert();
        store.upsert(new AlertCandidate("R1", 1, "R1|alice", List.of("e4", "e5"), "再次命中"));
        store.upsert(new AlertCandidate("R1", 1, "R1|alice", List.of("e6"), "第三次命中"));

        assertEquals(1, store.count());
        Alert alert = store.findAll().get(0);
        assertEquals(3, alert.hitCount());
        assertEquals(6, alert.eventIds().size());
        TestLog.pass("告警去重合并", "同链多次命中合并为一条告警并累计命中次数");
    }

    @Test
    @DisplayName("合法状态流转被记录且可追溯")
    void legalTransitionsAreAudited() {
        AlertStore store = storeWithOneAlert();
        AlertService service = new AlertService(store);
        String id = store.findAll().get(0).alertId();

        service.transition(id, AlertStatus.ACKNOWLEDGED, "值班确认");
        service.transition(id, AlertStatus.RESOLVED, "已处置");

        Alert alert = store.findAll().get(0);
        assertEquals(AlertStatus.RESOLVED, alert.status());
        assertEquals(2, alert.history().size());
        assertEquals(AlertStatus.NEW, alert.history().get(0).from());
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.history().get(0).to());
        assertEquals("值班确认", alert.history().get(0).reason());
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.history().get(1).from());
        assertEquals(AlertStatus.RESOLVED, alert.history().get(1).to());
        TestLog.pass("告警状态流转", "NEW->ACKNOWLEDGED->RESOLVED 全程留痕");
    }

    @Test
    @DisplayName("非法状态流转被拒绝")
    void illegalTransitionsRejected() {
        AlertStore store = storeWithOneAlert();
        AlertService service = new AlertService(store);
        String id = store.findAll().get(0).alertId();

        // NEW 不能直接 RESOLVED
        assertThrows(IllegalStateException.class,
                () -> service.transition(id, AlertStatus.RESOLVED, "跳级"));
        // 终态不可再流转
        service.transition(id, AlertStatus.SUPPRESSED, "误报抑制");
        assertThrows(IllegalStateException.class,
                () -> service.transition(id, AlertStatus.ACKNOWLEDGED, "终态回转"));
        assertEquals(AlertStatus.SUPPRESSED, store.findAll().get(0).status());
        TestLog.pass("告警状态流转", "跳级与终态回转均被拒绝");
    }

    @Test
    @DisplayName("不存在的告警流转报可定位错误")
    void unknownAlertRejected() {
        AlertService service = new AlertService(new AlertStore());
        assertThrows(IllegalArgumentException.class,
                () -> service.transition("ALT-999", AlertStatus.ACKNOWLEDGED, "无此告警"));
        TestLog.pass("告警状态流转", "未知告警ID给出明确错误");
    }
}
