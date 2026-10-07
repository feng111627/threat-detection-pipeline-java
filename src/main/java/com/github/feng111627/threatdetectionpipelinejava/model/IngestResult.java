package com.github.feng111627.threatdetectionpipelinejava.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 一批原始事件的接入结果：全部记录都必须落在 accepted 或 rejected 中。
 */
public class IngestResult {

    private final List<NormalizedEvent> accepted = new ArrayList<>();
    private final List<RejectedRecord> rejected = new ArrayList<>();

    public List<NormalizedEvent> accepted() {
        return accepted;
    }

    public List<RejectedRecord> rejected() {
        return rejected;
    }
}
