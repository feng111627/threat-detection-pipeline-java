package com.github.feng111627.threatdetectionpipelinejava.pipeline;

import com.github.feng111627.threatdetectionpipelinejava.alert.AlertService;
import com.github.feng111627.threatdetectionpipelinejava.alert.AlertStore;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventParser;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventSource;
import com.github.feng111627.threatdetectionpipelinejava.ingest.EventValidator;
import com.github.feng111627.threatdetectionpipelinejava.ingest.IngestionService;
import com.github.feng111627.threatdetectionpipelinejava.ingest.KeyValueEventParser;
import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.rule.DetectionRule;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleEngine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * 流水线装配：本地纯内存实现，不依赖任何外部服务。
 */
@Configuration
public class PipelineConfig {

    @Bean
    public List<EventParser> eventParsers() {
        return List.of(
                new KeyValueEventParser(EventSource.AUTH_LOG, new KeyValueEventParser.FieldMapping(
                        "aid", "time", "result", "server", "account",
                        Map.of("FAIL", EventType.LOGIN_FAILED, "OK", EventType.LOGIN_SUCCESS))),
                new KeyValueEventParser(EventSource.FIREWALL, new KeyValueEventParser.FieldMapping(
                        "fid", "ts", "action", "device", "user",
                        Map.of("SCAN", EventType.PORT_SCAN, "CONN", EventType.NETWORK_CONNECTION))),
                new KeyValueEventParser(EventSource.HOST_AGENT, new KeyValueEventParser.FieldMapping(
                        "hid", "ts", "op", "node", "user",
                        Map.of("EXEC", EventType.PROCESS_START, "READ", EventType.FILE_ACCESS))),
                new KeyValueEventParser(EventSource.IDS, new KeyValueEventParser.FieldMapping(
                        "iid", "ts", "sig", "sensor", "user",
                        Map.of("PORTSCAN", EventType.PORT_SCAN, "BRUTE", EventType.LOGIN_FAILED))));
    }

    @Bean
    public EventValidator eventValidator() {
        return new EventValidator(Clock.systemUTC(),
                Duration.ofMinutes(5), Duration.ofDays(30));
    }

    @Bean
    public IngestionService ingestionService(List<EventParser> parsers, EventValidator validator) {
        return new IngestionService(parsers, validator);
    }

    @Bean
    public RuleEngine ruleEngine() {
        RuleEngine engine = new RuleEngine();
        engine.loadRules(defaultRules());
        return engine;
    }

    /** 默认检测规则集，可通过 ruleEngine.loadRules 热更新（版本递增）。 */
    public static List<DetectionRule> defaultRules() {
        return List.of(
                DetectionRule.frequency("R-BRUTE-FORCE", 1,
                        java.util.Set.of(EventType.LOGIN_FAILED), 3,
                        Duration.ofMinutes(5), "user"),
                DetectionRule.threshold("R-PORT-SCAN", 1,
                        java.util.Set.of(EventType.PORT_SCAN), 10,
                        Duration.ofMinutes(1), "host", "ports"),
                DetectionRule.sequence("R-BREACH-PATH", 1,
                        List.of(EventType.LOGIN_FAILED, EventType.LOGIN_SUCCESS,
                                EventType.PROCESS_START),
                        Duration.ofMinutes(10), "user"));
    }

    @Bean
    public AlertStore alertStore() {
        return new AlertStore();
    }

    @Bean
    public AlertService alertService(AlertStore store) {
        return new AlertService(store);
    }

    @Bean
    public DetectionPipeline detectionPipeline(IngestionService ingestionService,
                                               RuleEngine ruleEngine,
                                               AlertStore alertStore) {
        return new DetectionPipeline(ingestionService, ruleEngine, alertStore);
    }
}
