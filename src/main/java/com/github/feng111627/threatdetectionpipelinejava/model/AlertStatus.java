package com.github.feng111627.threatdetectionpipelinejava.model;

/**
 * 告警状态：NEW -> ACKNOWLEDGED -> RESOLVED，RESOLVED 可重开，MERGED 为终态。
 */
public enum AlertStatus {
    NEW,
    ACKNOWLEDGED,
    RESOLVED,
    MERGED
}
