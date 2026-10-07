package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleType;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 窗口管理：按事件时间分配滚动窗口、维护 watermark、判定乱序/迟到、触发规则求值。
 *
 * <p>关键语义：
 * <ul>
 *   <li>窗口按「规则 × 分组 × 窗口起始」切分，窗口起始由事件时间向下取整得到，
 *       乱序/迟到事件仍归入其事件时间所属窗口，判定稳定可复现。</li>
 *   <li>watermark = max(eventTime) - allowedLateness。事件时间早于 watermark 视为迟到：
 *       迟到事件不再触发新告警（窗口已 finalize），仅登记，避免迟到数据污染结论。</li>
 *   <li>窗口内重复 eventId 被忽略；未关闭窗口的重复到达最多只触发一次。</li>
 *   <li>SEQUENCE 规则要求序列中的事件按事件时间在窗口内先后出现（非连续）。</li>
 * </ul>
 */
@Component
public class WindowManager {

    private final Clock clock;

    /** key = ruleId|groupValue */
    private final ConcurrentMap<String, GroupWindows> windowsByRuleGroup = new ConcurrentHashMap<>();

    public WindowManager(Clock clock) {
        this.clock = clock;
    }

    public EngineOutcome addEvent(DetectionRule rule, NormalizedEvent event, Instant currentWatermark) {
        EngineOutcome outcome = new EngineOutcome();
        if (!matches(rule, event)) {
            return outcome;
        }

        String groupValue = groupValue(rule, event);
        GroupWindows windows = windowsByRuleGroup.computeIfAbsent(
                rule.id() + "|" + groupValue,
                key -> new GroupWindows());

        long windowMs = rule.windowSeconds() * 1000L;
        long eventMs = event.eventTime().toEpochMilli();
        long windowStart = Math.floorDiv(eventMs, windowMs) * windowMs;

        synchronized (windows) {
            // 迟到判定：调用方按该规则的允许迟到折算过 watermark（maxEventTime - lateness）
            if (currentWatermark != null && eventMs < currentWatermark.toEpochMilli()) {
                outcome.setLate(true);
                return outcome;
            }

            WindowState state = windows.stateByStart.computeIfAbsent(
                    windowStart, start -> new WindowState(start, windowMs));

            if (!state.addEvent(event)) {
                // 重复事件：窗口内容不变，不重复触发
                return outcome;
            }

            evaluate(rule, groupValue, state, outcome.seeds());
        }
        return outcome;
    }

    /**
     * 关闭并移除所有 endMs + lateness &lt;= watermarkMs 的窗口。
     * 关闭本身不额外产出告警（告警在达到条件时已产出；迟到数据也不会再产出）。
     */
    public List<WindowKey> closeExpiredWindows(Instant currentWatermark) {
        List<WindowKey> closed = new ArrayList<>();
        long watermarkMs = currentWatermark.toEpochMilli();
        for (Map.Entry<String, GroupWindows> entry : windowsByRuleGroup.entrySet()) {
            String ruleAndGroup = entry.getKey();
            GroupWindows windows = entry.getValue();
            synchronized (windows) {
                windows.stateByStart.values().removeIf(state -> {
                    boolean expire = state.endMs() <= watermarkMs;
                    if (expire) {
                        state.setClosed(true);
                        int sep = ruleAndGroup.indexOf('|');
                        closed.add(new WindowKey(ruleAndGroup.substring(0, sep),
                                state.startMs(), ruleAndGroup.substring(sep + 1)));
                    }
                    return expire;
                });
            }
        }
        return closed;
    }

    private boolean matches(DetectionRule rule, NormalizedEvent event) {
        if (rule.matchEventType() != null && !rule.matchEventType().equals(event.eventType())) {
            return false;
        }
        if (rule.matchSource() != null && !rule.matchSource().equals(event.source())) {
            return false;
        }
        for (Map.Entry<String, String> expected : rule.matchAttributes().entrySet()) {
            String actual = event.attributes().get(expected.getKey());
            if (!expected.getValue().equals(actual)) {
                return false;
            }
        }
        return true;
    }

    private void evaluate(DetectionRule rule, String groupValue,
                          WindowState state, List<AlertSeed> seeds) {
        boolean hit;
        if (rule.type() == RuleType.SEQUENCE) {
            hit = matchesSequence(rule, state);
        } else {
            hit = state.events().size() >= rule.threshold();
        }
        if (hit && !state.isFired()) {
            state.setFired(true);
            seeds.add(buildSeed(rule, groupValue, state));
        }
    }

    private boolean matchesSequence(DetectionRule rule, WindowState state) {
        List<String> expected = rule.sequence();
        if (expected == null || expected.isEmpty()) {
            return false;
        }
        int cursor = 0;
        for (NormalizedEvent event : state.events()) {
            if (event.eventType().equals(expected.get(cursor))) {
                cursor++;
                if (cursor == expected.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    private AlertSeed buildSeed(DetectionRule rule, String groupValue, WindowState state) {
        List<NormalizedEvent> events = state.events();
        NormalizedEvent first = events.get(0);
        NormalizedEvent last = events.get(events.size() - 1);

        List<String> eventIds = events.stream().map(NormalizedEvent::eventId).toList();
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("windowStart", Instant.ofEpochMilli(state.startMs()).toString());
        evidence.put("windowEnd", Instant.ofEpochMilli(state.endMs()).toString());
        evidence.put("groupBy", rule.groupBy());
        evidence.put("groupValue", groupValue);
        evidence.put("matchedCount", events.size());
        evidence.put("firstEventId", first.eventId());
        evidence.put("lastEventId", last.eventId());

        long windowStart = state.startMs();
        return new AlertSeed(
                rule.id(),
                rule.version(),
                new WindowKey(rule.id(), windowStart, groupValue).correlationKey(),
                rule.severity(),
                rule.title() != null ? rule.title() : rule.id() + " 命中",
                first.eventTime(),
                Instant.now(clock),
                eventIds,
                evidence);
    }

    private static String groupValue(DetectionRule rule, NormalizedEvent event) {
        if (rule.groupBy() == null || rule.groupBy().isEmpty()) {
            return "*";
        }
        StringBuilder sb = new StringBuilder();
        for (String field : rule.groupBy()) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(extractField(event, field));
        }
        return sb.toString();
    }

    private static String extractField(NormalizedEvent event, String field) {
        return switch (field) {
            case "sourceIp" -> nullSafe(event.sourceIp());
            case "targetIp" -> nullSafe(event.targetIp());
            case "user" -> nullSafe(event.user());
            case "source" -> nullSafe(event.source());
            case "eventType" -> nullSafe(event.eventType());
            default -> event.attributes().getOrDefault(field, "-");
        };
    }

    private static String nullSafe(String value) {
        return value == null ? "-" : value;
    }

    /** 单个「规则 × 分组」下的所有窗口集合。 */
    private static final class GroupWindows {
        private final ConcurrentHashMap<Long, WindowState> stateByStart = new ConcurrentHashMap<>();
    }
}
