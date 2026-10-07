package com.github.feng111627.threatdetectionpipelinejava.rule;

/**
 * 规则加载器：从本地资源解析规则定义（JSON），不依赖外部服务。
 * 顶层 version 为配置版本；规则未单独声明版本时继承该版本。
 */
public interface RuleLoader {

    RuleSet loadFromClasspath(String resource);
}
