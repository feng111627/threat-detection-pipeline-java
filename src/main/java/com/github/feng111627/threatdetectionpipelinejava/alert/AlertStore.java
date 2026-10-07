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

    private final ConcurrentHashMap<String, Alert> alerts = new ConcurrentHashMap<>();

    public Optional<Alert> findById(String alertId) {
        return Optional.ofNullable(alerts.get(alertId));
    }

    public Optional<Alert> findByCorrelationKey(String correlationKey) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public List<Alert> findAll() {
        return new ArrayList<>(alerts.values());
    }

    public void put(Alert alert) {
        alerts.put(alert.alertId(), alert);
    }
}
