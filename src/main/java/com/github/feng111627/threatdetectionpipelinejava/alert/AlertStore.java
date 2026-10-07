package com.github.feng111627.threatdetectionpipelinejava.alert;

import com.github.feng111627.threatdetectionpipelinejava.rule.AlertCandidate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 并发安全的告警存储：按 (ruleId, chainKey) 去重。
 * 同一事件链的重复命中合并进已有告警，保证并发接入时告警数量一致。
 */
public class AlertStore {

    private record DedupKey(String ruleId, String chainKey) {
        static DedupKey of(AlertCandidate c) {
            return new DedupKey(c.ruleId(), c.chainKey());
        }
    }

    private final Map<DedupKey, Alert> alerts = new ConcurrentHashMap<>();
    private final Map<String, DedupKey> byAlertId = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong();

    /** 幂等 upsert：同链已存在则合并，否则新建。返回该链对应的告警。 */
    public Alert upsert(AlertCandidate candidate) {
        DedupKey key = DedupKey.of(candidate);
        Alert alert = alerts.computeIfAbsent(key, k -> {
            Alert created = new Alert("ALT-" + sequence.incrementAndGet(),
                    candidate.ruleId(), candidate.ruleVersion(), candidate.chainKey());
            byAlertId.put(created.alertId(), k);
            return created;
        });
        // 新建与重复命中都记一次合并（首次合并即初始化事件集）
        alert.merge(candidate.ruleVersion(), candidate.eventIds());
        return alert;
    }

    public Optional<Alert> findById(String alertId) {
        DedupKey key = byAlertId.get(alertId);
        return key == null ? Optional.empty() : Optional.ofNullable(alerts.get(key));
    }

    public List<Alert> findAll() {
        return List.copyOf(alerts.values());
    }

    public long count() {
        return alerts.size();
    }
}
