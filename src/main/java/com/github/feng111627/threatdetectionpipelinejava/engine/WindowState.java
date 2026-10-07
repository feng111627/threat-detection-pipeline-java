package com.github.feng111627.threatdetectionpipelinejava.engine;

import com.github.feng111627.threatdetectionpipelinejava.model.NormalizedEvent;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 单个窗口内的匹配事件状态。事件按事件时间有序维护，保证乱序到达时判定一致；
 * 同一事件 ID 只保留一次，保证重复到达不改变判定结果。
 */
public class WindowState {

    public static final Comparator<NormalizedEvent> EVENT_ORDER =
            Comparator.comparing(NormalizedEvent::eventTime)
                    .thenComparing(NormalizedEvent::eventId);

    private final long startMs;
    private final long windowMs;
    private final List<NormalizedEvent> events = new ArrayList<>();
    private boolean fired;
    private boolean closed;

    public WindowState(long startMs, long windowMs) {
        this.startMs = startMs;
        this.windowMs = windowMs;
    }

    public long startMs() {
        return startMs;
    }

    public long endMs() {
        return startMs + windowMs;
    }

    public List<NormalizedEvent> events() {
        return events;
    }

    public boolean isFired() {
        return fired;
    }

    public void setFired(boolean fired) {
        this.fired = fired;
    }

    public boolean isClosed() {
        return closed;
    }

    public void setClosed(boolean closed) {
        this.closed = closed;
    }

    /**
     * 有序插入事件；重复 eventId 直接忽略。
     *
     * @return true 表示新加入；false 表示窗口内已存在该事件
     */
    public boolean addEvent(NormalizedEvent event) {
        for (NormalizedEvent existing : events) {
            if (existing.eventId().equals(event.eventId())) {
                return false;
            }
        }
        events.add(event);
        events.sort(EVENT_ORDER);
        return true;
    }
}
