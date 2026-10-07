package com.github.feng111627.threatdetectionpipelinejava.ingest;

/**
 * 一条待接入的原始日志记录。
 */
public record RawRecord(EventSource source, String line) {
}
