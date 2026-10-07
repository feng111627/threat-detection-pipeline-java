package com.github.feng111627.threatdetectionpipelinejava.config;

import com.github.feng111627.threatdetectionpipelinejava.ingest.CsvSourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.ingest.JsonSourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.ingest.KeyValueSourceAdapter;
import com.github.feng111627.threatdetectionpipelinejava.ingest.SourceAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 本地接入层配置：注册各来源适配器与系统时钟（测试可替换为固定时钟）。
 */
@Configuration
public class IngestConfiguration {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public SourceAdapter firewallAdapter() {
        return new JsonSourceAdapter();
    }

    @Bean
    public SourceAdapter edrAdapter() {
        return new CsvSourceAdapter();
    }

    @Bean
    public SourceAdapter iamAdapter() {
        return new KeyValueSourceAdapter();
    }
}
