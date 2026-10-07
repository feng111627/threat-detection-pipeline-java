package com.github.feng111627.threatdetectionpipelinejava.pipeline;

import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectedRecord;

import java.util.ArrayList;
import java.util.List;

/**
 * 一次批次处理的完整结果：接入、拒绝、迟到、产出告警均可核对。
 * alerts 为本次实际新创建的告警（重复消费/同链补充不重复计入）。
 */
public class PipelineResult {

    private final List<NormalizedEvent> accepted = new ArrayList<>();
    private final List<RejectedRecord> rejected = new ArrayList<>();
    private final List<NormalizedEvent> late = new ArrayList<>();
    private final List<Alert> alerts = new ArrayList<>();

    public List<NormalizedEvent> accepted() {
        return accepted;
    }

    public List<RejectedRecord> rejected() {
        return rejected;
    }

    public List<NormalizedEvent> late() {
        return late;
    }

    public List<Alert> alerts() {
        return alerts;
    }

    public int totalIn() {
        return accepted.size() + rejected.size();
    }
}
