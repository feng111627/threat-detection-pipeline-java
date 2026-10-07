package com.github.feng111627.threatdetectionpipelinejava.pipeline;

import com.github.feng111627.threatdetectionpipelinejava.alert.AlertService;
import com.github.feng111627.threatdetectionpipelinejava.engine.AlertSeed;
import com.github.feng111627.threatdetectionpipelinejava.engine.DetectionEngine;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventNormalizer;
import com.github.feng111627.threatdetectionpipelinejava.model.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleRepository;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 端到端编排：事件接入/归一化 -> 规则检测/窗口关联 -> 告警产出。
 * 并发安全：可从多线程提交批次，结果保持一致。
 */
@Component
public class DetectionPipeline {

    private final EventNormalizer normalizer;
    private final DetectionEngine engine;
    private final AlertService alertService;
    private final RuleRepository ruleRepository;

    public DetectionPipeline(EventNormalizer normalizer,
                             DetectionEngine engine,
                             AlertService alertService,
                             RuleRepository ruleRepository) {
        this.normalizer = normalizer;
        this.engine = engine;
        this.alertService = alertService;
        this.ruleRepository = ruleRepository;
    }

    public PipelineResult processBatch(List<RawEvent> rawEvents) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public PipelineResult flush() {
        throw new UnsupportedOperationException("骨架占位");
    }
}
