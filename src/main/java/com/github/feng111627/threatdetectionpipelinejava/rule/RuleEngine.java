package com.github.feng111627.threatdetectionpipelinejava.rule;

import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 规则引擎：按事件时间把事件落入对齐到 epoch 的滚动窗口（tumbling window）。
 *
 * <p>语义约定：
 * <ul>
 *   <li>窗口按事件时间对齐，判定只依赖事件集合本身，与到达顺序无关，
 *       乱序/迟到事件落入各自窗口后独立判定，最终结果与顺序到达一致；</li>
 *   <li>窗口内按 eventId 去重，重复事件不影响计数；</li>
 *   <li>每个 (规则, 关联键, 窗口) 最多命中一次，重复消费不会重复产出；</li>
 *   <li>规则版本升级后该规则的窗口状态重置，历史告警保留旧版本号可复现。</li>
 * </ul>
 */
public class RuleEngine {

    /** 单个窗口桶：保存窗口内事件（按 eventId 去重）与命中标记。 */
    private static final class Bucket {
        final Map<String, SecurityEvent> eventsById = new LinkedHashMap<>();
        boolean fired;
    }

    private final Map<String, DetectionRule> rules = new LinkedHashMap<>();
    /** ruleId -> groupKey -> windowIndex -> Bucket */
    private final Map<String, Map<String, Map<Long, Bucket>>> windows = new HashMap<>();

    public synchronized void loadRules(List<DetectionRule> newRules) {
        for (DetectionRule rule : newRules) {
            DetectionRule old = rules.get(rule.ruleId());
            if (old == null || old.version() != rule.version()) {
                // 新规则或版本变化：重置该规则的窗口状态
                rules.put(rule.ruleId(), rule);
                windows.remove(rule.ruleId());
            }
        }
    }

    public synchronized List<AlertCandidate> evaluate(SecurityEvent event) {
        List<AlertCandidate> hits = new ArrayList<>();
        for (DetectionRule rule : rules.values()) {
            if (!rule.eventTypes().contains(event.type())) {
                continue;
            }
            String groupKey = groupKey(rule, event);
            long windowIndex = event.timestamp().toEpochMilli() / rule.window().toMillis();
            Bucket bucket = windows
                    .computeIfAbsent(rule.ruleId(), k -> new HashMap<>())
                    .computeIfAbsent(groupKey, k -> new TreeMap<>())
                    .computeIfAbsent(windowIndex, k -> new Bucket());
            if (bucket.eventsById.putIfAbsent(event.eventId(), event) != null) {
                continue; // 重复事件：窗口内幂等
            }
            if (!bucket.fired && matches(rule, bucket)) {
                bucket.fired = true;
                List<SecurityEvent> events = sortedEvents(bucket);
                hits.add(new AlertCandidate(
                        rule.ruleId(),
                        rule.version(),
                        rule.ruleId() + "|" + groupKey,
                        events.stream().map(SecurityEvent::eventId).sorted().toList(),
                        describe(rule, groupKey, windowIndex, events)));
            }
        }
        return hits;
    }

    private String groupKey(DetectionRule rule, SecurityEvent event) {
        return switch (rule.groupBy()) {
            case "user" -> event.user() == null ? "<none>" : event.user();
            case "host" -> event.host();
            default -> event.attributes().getOrDefault(rule.groupBy(), "<none>");
        };
    }

    private List<SecurityEvent> sortedEvents(Bucket bucket) {
        return bucket.eventsById.values().stream()
                .sorted((a, b) -> a.timestamp().compareTo(b.timestamp()))
                .toList();
    }

    private boolean matches(DetectionRule rule, Bucket bucket) {
        List<SecurityEvent> events = sortedEvents(bucket);
        return switch (rule.type()) {
            case FREQUENCY -> events.size() >= rule.threshold();
            case THRESHOLD -> events.stream().anyMatch(e -> {
                String raw = e.attributes().get(rule.valueField());
                if (raw == null) {
                    return false;
                }
                try {
                    return Long.parseLong(raw) >= rule.threshold();
                } catch (NumberFormatException ex) {
                    return false;
                }
            });
            case SEQUENCE -> containsSubsequence(events, rule.sequence());
        };
    }

    private boolean containsSubsequence(List<SecurityEvent> events, List<EventType> sequence) {
        int i = 0;
        for (SecurityEvent e : events) {
            if (e.type() == sequence.get(i) && ++i == sequence.size()) {
                return true;
            }
        }
        return false;
    }

    private String describe(DetectionRule rule, String groupKey, long windowIndex,
                            List<SecurityEvent> events) {
        return "规则 %s(v%d) 命中: 类型=%s 关联键=%s 窗口序号=%d 窗口内事件数=%d".formatted(
                rule.ruleId(), rule.version(), rule.type(), groupKey, windowIndex, events.size());
    }
}
