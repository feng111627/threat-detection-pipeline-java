package com.github.feng111627.threatdetectionpipelinejava.rule;

import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 规则仓库：加载规则资源，维护版本化的不可变快照（当前快照 + 历史快照）。
 * 告警固化规则版本，规则调整后历史结论仍可按当时快照复现。
 */
@Component
public class RuleRepository {

    public RuleSet current() {
        throw new UnsupportedOperationException("骨架占位");
    }

    public RuleSet load(String resource) {
        throw new UnsupportedOperationException("骨架占位");
    }

    public List<RuleSet> history() {
        throw new UnsupportedOperationException("骨架占位");
    }
}
