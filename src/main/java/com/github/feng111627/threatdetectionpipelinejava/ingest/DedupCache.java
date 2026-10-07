package com.github.feng111627.threatdetectionpipelinejava.ingest;

import org.springframework.stereotype.Component;

/**
 * 事件去重缓存：同一业务事件（来源 + 来源记录 ID）只允许进入检测链路一次，
 * 保证同一批数据重复消费不会重复产出告警。
 */
@Component
public class DedupCache {

    public boolean registerIfAbsent(String source, String sourceRecordId) {
        throw new UnsupportedOperationException("骨架占位");
    }
}
