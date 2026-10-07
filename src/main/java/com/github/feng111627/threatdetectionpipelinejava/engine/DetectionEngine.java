package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;
import com.github.feng111627.threatdetectionpipelinejava.rule.RuleSet;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 检测引擎：对归一化事件执行全部启用规则，并负责关闭过期窗口。
 */
@Component
public class DetectionEngine {

    public List<AlertSeed> process(NormalizedEvent event, RuleSet ruleSet) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public List<AlertSeed> flush(RuleSet ruleSet) {
        throw new UnsupportedOperationException("骨架占位");
    }
}
