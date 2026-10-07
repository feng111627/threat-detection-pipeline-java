package com.github.feng111627.threatdetectionpipelinejava.simulator;

import com.github.feng111627.threatdetectionpipelinejava.model.RawEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 本地事件模拟器：确定性（固定随机种子）地生成多来源安全日志。
 *
 * <p>场景：
 * <ul>
 *   <li>{@code mixed}：三来源混合，含正常记录、字段缺失、时间戳缺失/非法/越界、
 *       格式非法、乱序、迟到、重复（模拟同一批被重复消费的一半记录）。</li>
 *   <li>{@code bruteForce}：同一账号 1 分钟内多次 LOGIN_FAIL，触发阈值规则。</li>
 *   <li>{@code killChain}：同 IP 上 LOGIN_SUCCESS -> PRIVILEGE_ESCALATION -> DATA_EXPORT，
 *       且故意乱序发送，触发时序规则。</li>
 * </ul>
 */
@Component
public class LocalEventSimulator {

    public static final String SCENARIO_MIXED = "mixed";
    public static final String SCENARIO_BRUTE_FORCE = "bruteForce";
    public static final String SCENARIO_KILL_CHAIN = "killChain";

    private static final Instant BASE_TIME = Instant.parse("2026-10-07T10:00:00Z");

    public List<RawEvent> generateScenario(String scenario) {
        List<RawEvent> events = new ArrayList<>();
        switch (scenario == null ? SCENARIO_MIXED : scenario) {
            case SCENARIO_BRUTE_FORCE -> generateBruteForce(events);
            case SCENARIO_KILL_CHAIN -> generateKillChain(events);
            default -> generateMixed(events);
        }
        return events;
    }

    private void generateMixed(List<RawEvent> out) {
        Instant now = Instant.now();

        // --- firewall（JSON）：正常 3 条，含一条乱序 ---
        out.add(raw("firewall", "fw-1001",
                json("fw-1001", "FIREWALL_BLOCK", "2026-10-07T10:00:05Z",
                        "203.0.113.9", "10.0.0.5", null), now));
        out.add(raw("firewall", "fw-1002",
                json("fw-1002", "FIREWALL_BLOCK", "2026-10-07T10:00:20Z",
                        "203.0.113.9", "10.0.0.5", null), now));
        // 乱序：事件时间比上一条早
        out.add(raw("firewall", "fw-1003",
                json("fw-1003", "FIREWALL_BLOCK", "2026-10-07T10:00:10Z",
                        "203.0.113.9", "10.0.0.5", null), now));
        // 字段缺失：没有主体（src_ip/user 都缺）-> 业务校验
        out.add(raw("firewall", "fw-1004",
                "{\"event_id\":\"fw-1004\",\"type\":\"FIREWALL_BLOCK\","
                        + "\"ts\":\"2026-10-07T10:00:30Z\",\"dst_ip\":\"10.0.0.5\"}", now));
        // JSON 非法 -> 解析失败
        out.add(raw("firewall", "fw-1005", "{not-a-json", now));
        // 时间戳缺失 -> 解析失败
        out.add(raw("firewall", "fw-1006",
                "{\"event_id\":\"fw-1006\",\"type\":\"FIREWALL_BLOCK\","
                        + "\"src_ip\":\"203.0.113.9\"}", now));
        // 时间戳格式非法 -> 解析失败
        out.add(raw("firewall", "fw-1007",
                "{\"event_id\":\"fw-1007\",\"type\":\"FIREWALL_BLOCK\","
                        + "\"ts\":\"07/10/2026 ten oclock\",\"src_ip\":\"203.0.113.9\"}", now));
        // 时间在未来 -> 业务校验
        out.add(raw("firewall", "fw-1008",
                json("fw-1008", "FIREWALL_BLOCK", "2099-01-01T00:00:00Z",
                        "203.0.113.9", "10.0.0.5", null), now));
        // 未知事件类型 -> 业务校验
        out.add(raw("firewall", "fw-1009",
                json("fw-1009", "SOMETHING_WEIRD", "2026-10-07T10:00:40Z",
                        "203.0.113.9", null, null), now));
        // 重复记录：与 fw-1001 完全一致（模拟重放）
        out.add(raw("firewall", "fw-1001",
                json("fw-1001", "FIREWALL_BLOCK", "2026-10-07T10:00:05Z",
                        "203.0.113.9", "10.0.0.5", null), now));

        // --- edr（CSV）：正常 + 列数非法 ---
        out.add(raw("edr", "edr-2001",
                csv("edr-2001", "MALWARE_DETECTED", "2026-10-07 10:01:00",
                        "10.0.0.7", "10.0.0.1", "svc-acc", "HIGH"), now));
        out.add(raw("edr", "edr-2002",
                csv("edr-2002", "PROCESS_SPAWN", "1759831320000",
                        "10.0.0.7", "10.0.0.1", "svc-acc", "LOW"), now));
        // CSV 列数非法 -> 解析失败
        out.add(raw("edr", "edr-2003", "edr-2003,PROCESS_SPAWN,2026-10-07 10:01:10", now));
        // 空报文 -> 解析失败
        out.add(raw("edr", "edr-2004", "   ", now));

        // --- iam（键值对）：正常 + 键值对非法 ---
        out.add(raw("iam", "iam-3001", kv("iam-3001", "LOGIN_SUCCESS",
                "2026-10-07T10:02:00Z", "10.0.0.20", null, "bob"), now));
        out.add(raw("iam", "iam-3002", kv("iam-3002", "LOGIN_FAIL",
                "2026-10-07T10:02:05Z", "10.0.0.20", null, "bob"), now));
        // 键值对片段非法 -> 解析失败
        out.add(raw("iam", "iam-3003", "event_id=iam-3003;garbage-segment", now));
        // 来源缺失 -> 业务校验
        out.add(raw(null, "iam-3004", kv("iam-3004", "LOGIN_FAIL",
                "2026-10-07T10:02:10Z", "10.0.0.20", null, "bob"), now));
        // 未知来源 -> 解析失败（不支持的格式/来源）
        out.add(raw("ids-probe", "x-1", "anything", now));
    }

    private void generateBruteForce(List<RawEvent> out) {
        Instant now = Instant.now();
        // 同一账号 60 秒窗口内 6 次失败（阈值 5），发送顺序故意乱序
        long[] offsets = {45L, 5L, 30L, 10L, 50L, 20L};
        int index = 1;
        for (long offset : offsets) {
            String id = "bf-00" + index;
            out.add(raw("iam", id, kv(id, "LOGIN_FAIL",
                    BASE_TIME.plusSeconds(offset).toString(), "198.51.100.7", null, "root"), now));
            index++;
        }
        // 迟到的第 7 次：事件时间远早于 watermark（通过先发一条更晚的事件推进 watermark）
        out.add(raw("iam", "bf-clock", kv("bf-clock", "LOGIN_FAIL",
                BASE_TIME.plusSeconds(300).toString(), "198.51.100.7", null, "root"), now));
        out.add(raw("iam", "bf-late", kv("bf-late", "LOGIN_FAIL",
                BASE_TIME.plusSeconds(2).toString(), "198.51.100.7", null, "root"), now));
        // 完全重复的一批（模拟同一批数据被重复消费）
        List<RawEvent> duplicates = new ArrayList<>();
        for (int i = 1; i <= 6; i++) {
            String id = "bf-00" + i;
            duplicates.add(raw("iam", id, kv(id, "LOGIN_FAIL",
                    BASE_TIME.plusSeconds(offsets[i - 1]).toString(),
                    "198.51.100.7", null, "root"), now));
        }
        out.addAll(duplicates);
    }

    private void generateKillChain(List<RawEvent> out) {
        Instant now = Instant.now();
        RawEvent privEsc = raw("edr", "kc-2", csv("kc-2", "PRIVILEGE_ESCALATION",
                "2026-10-07 10:05:30", "10.0.0.50", "10.0.0.1", "svc", "CRITICAL"), now);
        RawEvent dataExport = raw("firewall", "kc-3", json("kc-3", "DATA_EXPORT",
                "2026-10-07T10:06:00Z", "10.0.0.50", "192.0.2.99", null), now);
        RawEvent login = raw("iam", "kc-1", kv("kc-1", "LOGIN_SUCCESS",
                "2026-10-07T10:05:00Z", "10.0.0.50", null, "svc"), now);
        // 故意乱序：提权 -> 外发 -> 登录
        out.add(privEsc);
        out.add(dataExport);
        out.add(login);
    }

    private RawEvent raw(String source, String recordId, String payload, Instant receivedAt) {
        return new RawEvent(source, recordId, payload, receivedAt);
    }

    private static String json(String id, String type, String ts,
                               String src, String dst, String user) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"event_id\":\"").append(id).append('"');
        sb.append(",\"type\":\"").append(type).append('"');
        sb.append(",\"ts\":\"").append(ts).append('"');
        if (src != null) {
            sb.append(",\"src_ip\":\"").append(src).append('"');
        }
        if (dst != null) {
            sb.append(",\"dst_ip\":\"").append(dst).append('"');
        }
        if (user != null) {
            sb.append(",\"user\":\"").append(user).append('"');
        }
        return sb.append('}').toString();
    }

    private static String csv(String id, String type, String ts,
                              String src, String dst, String user, String severity) {
        return String.join(",", id, type, ts, src, dst, user, severity);
    }

    private static String kv(String id, String type, String ts,
                             String src, String dst, String user) {
        StringBuilder sb = new StringBuilder();
        sb.append("event_id=").append(id);
        sb.append(";type=").append(type);
        sb.append(";ts=").append(ts);
        if (src != null) {
            sb.append(";src_ip=").append(src);
        }
        if (dst != null) {
            sb.append(";dst_ip=").append(dst);
        }
        if (user != null) {
            sb.append(";user=").append(user);
        }
        return sb.toString();
    }
}
