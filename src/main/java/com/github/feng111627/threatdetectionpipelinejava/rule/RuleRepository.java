package com.github.feng111627.threatdetectionpipelinejava.rule;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 规则仓库：加载规则资源，维护版本化的不可变快照（当前快照 + 历史快照）。
 * 告警固化规则版本，规则调整后历史结论仍可按当时快照复现。
 */
@Component
public class RuleRepository {

    private final RuleLoader loader;
    private final AtomicReference<RuleSet> current = new AtomicReference<>();
    private final CopyOnWriteArrayList<RuleSet> history = new CopyOnWriteArrayList<>();

    public RuleRepository(RuleLoader loader,
                          @Value("${threat.rules-resource:rules-default.json}") String defaultResource) {
        this.loader = loader;
        this.current.set(load(defaultResource));
    }

    public RuleSet current() {
        return current.get();
    }

    public RuleSet load(String resource) {
        RuleSet ruleSet = loader.loadFromClasspath(resource);
        RuleSet previous = current.getAndSet(ruleSet);
        if (previous != null) {
            history.addIfAbsent(previous);
        }
        history.addIfAbsent(ruleSet);
        return ruleSet;
    }

    public List<RuleSet> history() {
        return new ArrayList<>(history);
    }
}
