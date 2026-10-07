package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * 单个窗口内的匹配事件状态（按事件时间排序维护，支持乱序/迟到/重复判定）。
 */
public class WindowState {

    private final List<NormalizedEvent> events = new ArrayList<>();
    private boolean closed;

    public List<NormalizedEvent> events() {
        return events;
    }

    public boolean isClosed() {
        return closed;
    }

    public void setClosed(boolean closed) {
        this.closed = closed;
    }
}
