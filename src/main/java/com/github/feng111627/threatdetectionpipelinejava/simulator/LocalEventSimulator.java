package com.github.feng111627.threatdetectionpipelinejava.simulator;

import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 本地事件模拟器：确定性（固定随机种子）地生成多来源安全日志，
 * 覆盖正常、字段缺失、时间戳异常/非法、乱序、迟到、重复等情形。
 */
@Component
public class LocalEventSimulator {

    public List<RawEvent> generateScenario(String scenario) {
        throw new UnsupportedOperationException("骨架占位");
    }
}
