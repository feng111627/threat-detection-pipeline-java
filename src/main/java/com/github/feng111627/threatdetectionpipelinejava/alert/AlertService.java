package com.github.feng111627.threatdetectionpipelinejava.alert;

import com.github.feng111627.threatdetectionpipelinejava.engine.AlertSeed;
import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.AlertStatus;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 告警服务：去重落库、按事件链合并、合法状态流转并记录可追溯历史。
 */
@Service
public class AlertService {

    private final AlertStore store;

    public AlertService(AlertStore store) {
        this.store = store;
    }

    public Alert ingestSeed(AlertSeed seed) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public Alert transition(String alertId, AlertStatus target, String operator, String reason) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public Alert merge(String childAlertId, String parentAlertId, String operator) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public List<Alert> allAlerts() {
        return store.findAll();
    }
}
