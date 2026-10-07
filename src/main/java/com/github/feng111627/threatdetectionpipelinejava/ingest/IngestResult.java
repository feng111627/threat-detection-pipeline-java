package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.RejectionRecord;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;

/**
 * 接入结果：要么接受（含归一化事件），要么拒绝（含原因），要么重复（幂等忽略）。
 */
public record IngestResult(Status status, SecurityEvent event, RejectionRecord rejection) {

    public enum Status {
        ACCEPTED,
        REJECTED,
        DUPLICATE
    }

    public static IngestResult accepted(SecurityEvent event) {
        return new IngestResult(Status.ACCEPTED, event, null);
    }

    public static IngestResult rejected(RejectionRecord rejection) {
        return new IngestResult(Status.REJECTED, null, rejection);
    }

    public static IngestResult duplicate(SecurityEvent event) {
        return new IngestResult(Status.DUPLICATE, event, null);
    }
}
