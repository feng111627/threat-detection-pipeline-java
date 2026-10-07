package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 窗口管理：按事件时间分配窗口、维护 watermark、判定乱序/迟到、触发规则求值。
 */
@Component
public class WindowManager {

    public List<AlertSeed> addEvent(DetectionRule rule, NormalizedEvent event, Instant currentWatermark) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public Optional<List<AlertSeed>> closeExpiredWindows(Instant currentWatermark) {
        throw new UnsupportedOperationException("骨架占位");
    }
}
