package com.github.feng111627.threatdetectionpipelinejava.alert;

import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 告警内存存储（本地能力），线程安全。
 */
@Component
public class AlertStore {

    private final ConcurrentHashMap<String, Alert> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> alertIdByCorrelationKey = new ConcurrentHashMap<>();

    public Optional<Alert> findById(String alertId) {
        return Optional.ofNullable(byId.get(alertId));
    }

    public Optional<Alert> findByCorrelationKey(String correlationKey) {
        String id = alertIdByCorrelationKey.get(correlationKey);
        return id == null ? Optional.empty() : Optional.ofNullable(byId.get(id));
    }

    public List<Alert> findAll() {
        return new ArrayList<>(byId.values());
    }

    /**
     * 落库一条新告警并建立 correlationKey 索引。
     *
     * @return true 表示新建成功；false 表示该 correlationKey 已存在（幂等命中）
     */
    public boolean putIfAbsent(Alert alert) {
        String previous = alertIdByCorrelationKey.putIfAbsent(alert.correlationKey(), alert.alertId());
        if (previous != null) {
            return false;
        }
        byId.put(alert.alertId(), alert);
        return true;
    }

    public Alert put(Alert alert) {
        byId.put(alert.alertId(), alert);
        return alert;
    }
}
