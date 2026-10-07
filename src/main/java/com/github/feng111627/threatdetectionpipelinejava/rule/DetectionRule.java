package com.github.feng111627.threatdetectionpipelinejava.rule;

import com.github.feng111627.threatdetectionpipelinejava.model.EventType;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * 可配置检测规则。version 随规则调整递增，告警记录 version 以复现历史结论。
 *
 * <p>三种类型：
 * <ul>
 *   <li>THRESHOLD：窗口内单条事件的数值属性 valueField 达到 threshold 即命中；</li>
 *   <li>FREQUENCY：窗口内匹配 eventTypes 的事件数达到 threshold 即命中；</li>
 *   <li>SEQUENCE：窗口内按事件时间排序后出现 sequence 指定的类型子序列即命中。</li>
 * </ul>
 * groupBy 指定关联维度（user / host / 属性名），同组事件构成一条事件链。
 */
public record DetectionRule(
        String ruleId,
        int version,
        RuleType type,
        Set<EventType> eventTypes,
        List<EventType> sequence,
        int threshold,
        Duration window,
        String groupBy,
        String valueField) {

    public static DetectionRule frequency(String ruleId, int version, Set<EventType> types,
                                          int threshold, Duration window, String groupBy) {
        return new DetectionRule(ruleId, version, RuleType.FREQUENCY, types,
                List.of(), threshold, window, groupBy, null);
    }

    public static DetectionRule threshold(String ruleId, int version, Set<EventType> types,
                                          int threshold, Duration window, String groupBy,
                                          String valueField) {
        return new DetectionRule(ruleId, version, RuleType.THRESHOLD, types,
                List.of(), threshold, window, groupBy, valueField);
    }

    public static DetectionRule sequence(String ruleId, int version, List<EventType> sequence,
                                         Duration window, String groupBy) {
        return new DetectionRule(ruleId, version, RuleType.SEQUENCE,
                Set.copyOf(sequence), sequence, sequence.size(), window, groupBy, null);
    }
}
