package com.github.feng111627.threatdetectionpipelinejava.pipeline;

import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStore;
import com.github.feng111627.threatdetectionpipelinejava.ingest.IngestResult;
import com.github.feng111627.threatdetectionpipelinejava.ingest.IngestionService;
import com.github.feng111627.threatdetectionpipelinejava.ingest.RawRecord;
import com.github.feng111627.threatdetectionpipelinejava.rule.AlertCandidate;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleEngine;

/**
 * 端到端流水线：接入(解析/校验/幂等) -> 规则检测 -> 告警去重合并。
 * 线程安全，可被多线程并发提交。
 */
public class DetectionPipeline {

    private final IngestionService ingestionService;
    private final RuleEngine ruleEngine;
    private final AlertStore alertStore;

    public DetectionPipeline(IngestionService ingestionService,
                             RuleEngine ruleEngine,
                             AlertStore alertStore) {
        this.ingestionService = ingestionService;
        this.ruleEngine = ruleEngine;
        this.alertStore = alertStore;
    }

    public IngestResult submit(RawRecord record) {
        IngestResult result = ingestionService.ingest(record);
        if (result.status() == IngestResult.Status.ACCEPTED) {
            for (AlertCandidate candidate : ruleEngine.evaluate(result.event())) {
                alertStore.upsert(candidate);
            }
        }
        return result;
    }
}
