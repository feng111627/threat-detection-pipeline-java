package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RejectionReason;

/**
 * 业务校验阶段异常：对应 RejectionCategory.VALIDATION 的拒绝原因。
 */
public class EventValidationException extends Exception {

    private final RejectionReason reason;

    public EventValidationException(RejectionReason reason, String detail) {
        super(reason.code() + ": " + reason.defaultMessage() + " - " + detail);
        this.reason = reason;
    }

    public RejectionReason reason() {
        return reason;
    }
}
