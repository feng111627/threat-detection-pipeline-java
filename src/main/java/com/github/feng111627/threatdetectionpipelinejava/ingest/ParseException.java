package com.github.feng111627.threatdetectionpipelinejava.ingest;

/**
 * 解析阶段失败：格式非法、字段缺失、时间戳异常等。
 */
public class ParseException extends Exception {
    public ParseException(String message) {
        super(message);
    }
}
