package com.github.feng111627.threatdetectionpipelinejava.rule;

import com.github.feng111627.threatdetectionpipelinejava.model.Severity;

import java.util.List;
import java.util.Map;

/**
 * 可配置的检测规则。
 *
 * @param version        规则版本，固化到告警上，保证历史可复现
 * @param type           规则类型
 * @param matchEventType 匹配的事件类型（null 表示不限定）
 * @param matchSource    匹配的事件来源（null 表示不限定）
 * @param matchAttributes 属性精确匹配（全部满足才算命中）
 * @param threshold      THRESHOLD/FREQUENCY 的触发阈值
 * @param windowSeconds  窗口长度（秒）
 * @param allowedLatenessSeconds 允许迟到时间（秒），超过后事件视为迟到，不再触发新告警
 * @param sequence       SEQUENCE 的事件类型序列（按事件时间先后）
 * @param groupBy        关联分组字段（sourceIp / user / targetIp ...）
 */
public record DetectionRule(
        String id,
        String version,
        boolean enabled,
        RuleType type,
        String matchEventType,
        String matchSource,
        Map<String, String> matchAttributes,
        int threshold,
        long windowSeconds,
        long allowedLatenessSeconds,
        List<String> sequence,
        List<String> groupBy,
        Severity severity,
        String title) {
}
