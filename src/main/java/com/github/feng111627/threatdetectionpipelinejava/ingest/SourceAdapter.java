package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;

/**
 * 来源适配器：把某一来源的原始报文解析为统一的 ParsedEvent。
 * 不同来源（JSON / CSV / 键值对）各自实现。
 */
public interface SourceAdapter {

    String sourceName();

    ParsedEvent parse(RawEvent raw) throws EventParseException;
}
