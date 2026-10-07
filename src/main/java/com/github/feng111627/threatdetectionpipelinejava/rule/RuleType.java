package com.github.feng111627.threatdetectionpipelinejava.rule;

/**
 * 规则类型：
 * THRESHOLD - 阈值计数（窗口内匹配事件数达到阈值）
 * FREQUENCY - 频率（窗口内匹配事件数达到阈值，语义与 THRESHOLD 一致，独立命名便于扩展）
 * SEQUENCE  - 时序关系（窗口内按事件时间依次出现指定事件类型序列）
 */
public enum RuleType {
    THRESHOLD,
    FREQUENCY,
    SEQUENCE
}
