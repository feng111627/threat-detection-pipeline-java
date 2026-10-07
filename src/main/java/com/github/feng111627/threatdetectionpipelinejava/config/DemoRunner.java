package com.github.feng111627.threatdetectionpipelinejava.config;

import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.AlertStatus;
import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import com.github.feng111627.threatdetectionpipelinejava.model.RejectedRecord;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.DetectionPipeline;
import com.github.feng111627.threatdetectionpipelinejava.pipeline.PipelineResult;
import com.github.feng111627.threatdetectionpipelinejava.simulator.LocalEventSimulator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 本地演示入口：加 --demo 参数后运行全部模拟场景，
 * 打印 接入/拒绝原因/告警产出/状态流转 的可解释结果。不影响测试。
 */
@Component
public class DemoRunner implements CommandLineRunner {

    private final DetectionPipeline pipeline;
    private final LocalEventSimulator simulator;

    public DemoRunner(DetectionPipeline pipeline, LocalEventSimulator simulator) {
        this.pipeline = pipeline;
        this.simulator = simulator;
    }

    @Override
    public void run(String... args) {
        if (args == null || args.length == 0 || !"--demo".equals(args[0])) {
            return;
        }
        runScenario(LocalEventSimulator.SCENARIO_MIXED, "多来源混合（坏数据/乱序/重复）");
        runScenario(LocalEventSimulator.SCENARIO_BRUTE_FORCE, "暴力破解（阈值/乱序/迟到/重复消费）");
        runScenario(LocalEventSimulator.SCENARIO_KILL_CHAIN, "攻击链（乱序时序关联）");
    }

    private void runScenario(String scenario, String description) {
        System.out.println();
        System.out.println("================ 场景: " + description + " ================");
        pipeline.reset();
        List<RawEvent> events = simulator.generateScenario(scenario);
        System.out.println("生成原始记录 " + events.size() + " 条");

        PipelineResult result = pipeline.processBatch(events);
        System.out.println("接入成功 " + result.accepted().size() + " 条（含去重后），其中迟到不计入 "
                + result.late().size() + " 条");
        System.out.println("拒绝 " + result.rejected().size() + " 条:");
        for (RejectedRecord rejected : result.rejected()) {
            System.out.println("  - [" + rejected.reason().category() + " " + rejected.reason().code()
                    + "] source=" + rejected.rawEvent().source()
                    + " recordId=" + rejected.rawEvent().sourceRecordId()
                    + " 原因=" + rejected.detail());
        }
        System.out.println("新产出告警 " + result.alerts().size() + " 条:");
        for (Alert alert : result.alerts()) {
            System.out.println("  * " + alert.alertId() + " [" + alert.severity() + "/"
                    + alert.status() + "] " + alert.title()
                    + " 规则=" + alert.ruleId() + "@" + alert.ruleVersion()
                    + " 关联键=" + alert.correlationKey()
                    + " 事件数=" + alert.eventIds().size());
        }

        // 同一批数据重复消费：不应产生新告警
        PipelineResult replay = pipeline.processBatch(events);
        System.out.println("重复消费后：接入 " + replay.accepted().size()
                + " 条，拒绝(重复) " + replay.rejected().size()
                + " 条，新告警 " + replay.alerts().size() + " 条");
        if (!replay.alerts().isEmpty()) {
            System.out.println("  [警告] 重复消费产生了新告警，幂等性被破坏");
        }

        // 演示一次合法/非法状态流转
        if (!result.alerts().isEmpty()) {
            Alert first = result.alerts().get(0);
            pipeline.flush();
            System.out.println("状态流转演示: " + first.alertId());
            for (var transition : first.history()) {
                System.out.println("    " + transition.from() + " -> " + transition.to()
                        + " by " + transition.operator() + " (" + transition.reason() + ")");
            }
        }
    }
}
