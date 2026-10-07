package com.github.feng111627.threatdetectionpipelinejava.ingest;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 事件去重缓存：同一业务事件（来源 + 来源记录 ID）只允许进入检测链路一次，
 * 保证同一批数据重复消费不会重复产出告警。
 *
 * <p>若来源没有提供记录 ID，则退化为对原始报文做 SHA-1 指纹，保证同报文重复仍可去重。
 */
@Component
public class DedupCache {

    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    /**
     * 注册一个业务事件指纹。
     *
     * @return true 表示首次出现（允许进入后续链路）；false 表示重复
     */
    public boolean registerIfAbsent(String source, String sourceRecordId, String rawPayload) {
        String identity = source + "|" + (sourceRecordId == null || sourceRecordId.isBlank()
                ? fingerprint(rawPayload)
                : sourceRecordId);
        return seen.add(identity);
    }

    private static String fingerprint(String payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8));
            return "sha1:" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 不可用", e);
        }
    }

    public void clear() {
        seen.clear();
    }
}
