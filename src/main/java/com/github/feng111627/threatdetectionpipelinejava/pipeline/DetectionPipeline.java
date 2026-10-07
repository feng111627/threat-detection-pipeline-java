package com.github.feng111627.threatdetectionpipelinejava.pipeline;

import com.github.feng111627.threatdetectionpipelinejava.alert.AlertService;
import com.github.feng111627.threatdetectionpipelinejava.engine.AlertSeed;
import com.github.feng111627.threatdetectionpipelinejava.engine.DetectionEngine;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventNormalizer;
import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleRepository;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleSet;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 端到端编排：事件接入/归一化 -> 规则检测/窗口关联 -> 告警产出。
 *
 * <p>并发安全：批次级锁串行化引擎与告警落库，保证并发接入时告警数量、状态一致；
 * 幂等由去重缓存（事件级）与 correlationKey（告警级）双重保证。
 */
@Component
public class DetectionPipeline {

    private final EventNormalizer normalizer;
    private final DetectionEngine engine;
    private final AlertService alertService;
    private final RuleRepository ruleRepository;
    private final Object batchLock = new Object();

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
        synchronized (batchLock) {
            PipelineResult result = new PipelineResult();
            RuleSet ruleSet = ruleRepository.current();

            IngestResult ingestResult = normalizer.ingest(rawEvents);
            result.rejected().addAll(ingestResult.rejected());
            result.accepted().addAll(ingestResult.accepted());

            for (NormalizedEvent event : ingestResult.accepted()) {
                List<AlertSeed> seeds = engine.process(event, ruleSet);
                for (AlertSeed seed : seeds) {
                    Alert before = alertService.findByCorrelationKey(seed.correlationKey());
                    Alert alert = alertService.ingestSeed(seed);
                    if (before == null) {
                        result.alerts().add(alert);
                    }
                }
            }
            return result;
        }
    }

    /** 按 wall-clock 推进 watermark、关闭过期窗口。 */
    public PipelineResult flush() {
        synchronized (batchLock) {
            PipelineResult result = new PipelineResult();
            engine.flush(ruleRepository.current());
            return result;
        }
    }
}
