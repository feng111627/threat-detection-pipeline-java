package com.github.feng111627.threatdetectionpipelinejava.engine;

/**
 * 窗口键：规则 + 窗口起始时间戳 + 关联分组。
 * 归属同一事件链的事件落在同一个窗口/分组内，触发的告警通过 correlationKey 合并。
 */
public record WindowKey(String ruleId, long windowStartEpochMs, String groupValue) {

    public String correlationKey() {
        return ruleId + "|" + windowStartEpochMs + "|" + groupValue;
    }
}
