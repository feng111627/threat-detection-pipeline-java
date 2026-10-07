package com.github.feng111627.threatdetectionpipelinejava.model;

/**
 * 归一化后的安全事件类型。
 */
public enum EventType {
    LOGIN_FAILED,
    LOGIN_SUCCESS,
    PORT_SCAN,
    FILE_ACCESS,
    PROCESS_START,
    NETWORK_CONNECTION
}
