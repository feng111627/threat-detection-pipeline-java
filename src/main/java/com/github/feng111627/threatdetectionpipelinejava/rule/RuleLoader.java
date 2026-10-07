package com.github.feng111627.threatdetectionpipelinejava.rule;

import java.util.List;

/**
 * 规则加载器：从本地资源解析规则定义（JSON），不依赖外部服务。
 */
public interface RuleLoader {

    List<DetectionRule> loadFromClasspath(String resource);
}
