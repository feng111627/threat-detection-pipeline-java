package com.github.feng111627.threatdetectionpipelinejava.config;

import com.github.feng111627.threatdetectionpipelinejava.pipeline.DetectionPipeline;
import com.github.feng111627.threatdetectionpipelinejava.simulator.LocalEventSimulator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * 本地演示入口：启动后运行模拟器，打印接入/拒绝/告警的可解释结果。
 * 通过 --demo 参数开启，避免影响测试。
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
        throw new UnsupportedOperationException("骨架占位");
    }
}
