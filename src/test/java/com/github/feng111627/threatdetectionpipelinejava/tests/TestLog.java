package com.github.feng111627.threatdetectionpipelinejava.tests;

/**
 * 测试日志工具：让运行日志能看出覆盖的业务场景与各用例通过情况。
 */
final class TestLog {
    private TestLog() {
    }

    static void pass(String scenario, String caseName) {
        System.out.printf("[业务场景] %s | 用例: %s => 通过%n", scenario, caseName);
    }
}
