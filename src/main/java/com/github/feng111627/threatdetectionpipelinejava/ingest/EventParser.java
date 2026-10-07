package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;

/**
 * 按来源解析原始日志为归一化事件。
 */
public interface EventParser {
    EventSource supports();

    SecurityEvent parse(RawRecord record) throws ParseException;
}
