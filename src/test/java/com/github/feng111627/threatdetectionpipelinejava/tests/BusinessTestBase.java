package com.github.feng111627.threatdetectionpipelinejava.tests;

import org.junit.jupiter.api.extension.TestWatcher;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 业务测试基类：在测试日志中统一打印
 * 「覆盖业务 / 用例 / 通过或失败」，保证运行测试即可看出业务覆盖与通过情况。
 */
@ExtendWith(BusinessTestBase.BusinessResultLogger.class)
public abstract class BusinessTestBase {

    public static class BusinessResultLogger implements TestWatcher {

        @Override
        public void testSuccessful(ExtensionContext context) {
            System.out.println("    [通过] " + name(context));
            System.out.flush();
        }

        @Override
        public void testFailed(ExtensionContext context, Throwable cause) {
            System.out.println("    [失败] " + name(context) + " -> " + cause);
            System.out.flush();
        }

        private static String name(ExtensionContext context) {
            return context.getDisplayName();
        }
    }

    /** 业务分组注解：打印类名时更易读。 */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface BusinessArea {
        String value();
    }
}
