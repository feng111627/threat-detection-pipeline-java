package com.github.feng111627.threatdetectionpipelinejava.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * 单条事件对某条规则的求值结果：是否匹配、是否迟到、本次新触发的告警种子。
 */
public class EngineOutcome {

    private final List<AlertSeed> seeds = new ArrayList<>();
    private boolean matched;
    private boolean late;

    public List<AlertSeed> seeds() {
        return seeds;
    }

    public boolean isMatched() {
        return matched;
    }

    public void setMatched(boolean matched) {
        this.matched = matched;
    }

    public boolean isLate() {
        return late;
    }

    public void setLate(boolean late) {
        this.late = late;
    }
}
