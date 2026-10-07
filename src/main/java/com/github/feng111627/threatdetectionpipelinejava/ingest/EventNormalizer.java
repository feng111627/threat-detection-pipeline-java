package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 事件接入与归一化：编排 解析 -> 业务校验 -> 去重，任何记录都不允许静默丢弃。
 */
@Component
public class EventNormalizer {

    public IngestResult ingest(List<RawEvent> rawEvents) {
        throw new UnsupportedOperationException("骨架占位");
    }
}
