package com.github.feng111627.threatdetectionpipelinejava.model;

/**
 * 拒绝发生的阶段：解析失败 与 业务校验不通过 可区分定位。
 */
public enum RejectStage {
    PARSE,
    VALIDATE
}
