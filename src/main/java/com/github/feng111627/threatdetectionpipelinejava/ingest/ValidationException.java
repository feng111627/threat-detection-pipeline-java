package com.github.feng111627.threatdetectionpipelinejava.ingest;

/**
 * 业务校验阶段失败：解析成功但语义不合法。
 */
public class ValidationException extends Exception {
    public ValidationException(String message) {
        super(message);
    }
}
