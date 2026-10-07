package com.github.feng111627.threatdetectionpipelinejava.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * 单条事件进入引擎后的结果：可能触发的告警种子，以及是否被判定为迟到事件。
 */
public class EngineOutcome {

    private final List<AlertSeed> seeds = new ArrayList<>();
    private boolean late;

    public List<AlertSeed> seeds() {
        return seeds;
    }

    public boolean isLate() {
        return late;
    }

    public void setLate(boolean late) {
        this.late = late;
    }
}
