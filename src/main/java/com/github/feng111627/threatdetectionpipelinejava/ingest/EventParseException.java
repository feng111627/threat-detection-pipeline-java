package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;

/**
 * 解析阶段异常：对应 RejectionCategory.PARSE 的拒绝原因。
 */
public class EventParseException extends Exception {

    private final RejectionReason reason;

    public EventParseException(RejectionReason reason, String detail) {
        super(reason.code() + ": " + reason.defaultMessage() + " - " + detail);
        this.reason = reason;
    }

    public RejectionReason reason() {
        return reason;
    }
}
