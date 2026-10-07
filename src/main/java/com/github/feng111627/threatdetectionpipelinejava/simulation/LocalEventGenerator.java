package com.github.feng111627.threatdetectionpipelinejava.simulation;

import com.github.feng111627.threatdetectionpipelinejava.ingest.EventSource;
import com.github.feng111627.threatdetectionpipelinejava.ingest.RawRecord;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * 本地事件生成器：模拟多来源安全日志（key=value 文本行），
 * 提供乱序与重复样本的构造工具，全部本地生成，不接外部服务。
 */
public class LocalEventGenerator {

    private final Random random;
    private final Instant baseTime;

    public LocalEventGenerator(long seed, Instant baseTime) {
        this.random = new Random(seed);
        this.baseTime = baseTime;
    }

    /** 生成 count 条混合来源的合法日志。 */
    public List<RawRecord> generate(int count) {
        List<RawRecord> records = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            records.add(switch (random.nextInt(4)) {
                case 0 -> authLog("u" + random.nextInt(5), i);
                case 1 -> firewall(i);
                case 2 -> hostAgent("u" + random.nextInt(5), i);
                default -> ids(i);
            });
        }
        return records;
    }

    /** AUTH_LOG：登录失败。 */
    public RawRecord authLog(String user, int seq) {
        return new RawRecord(EventSource.AUTH_LOG,
                "aid=auth-%d time=%s result=FAIL server=web%d account=%s".formatted(
                        seq, baseTime.plusSeconds(seq).toString(), seq % 3, user));
    }

    /** FIREWALL：端口扫描，ports 属性供阈值规则使用。 */
    public RawRecord firewall(int seq) {
        return new RawRecord(EventSource.FIREWALL,
                "fid=fw-%d ts=%s action=SCAN device=fw%d ports=%d".formatted(
                        seq, baseTime.plusSeconds(seq).toString(), seq % 2, 5 + random.nextInt(20)));
    }

    /** HOST_AGENT：进程启动。 */
    public RawRecord hostAgent(String user, int seq) {
        return new RawRecord(EventSource.HOST_AGENT,
                "hid=host-%d ts=%s op=EXEC node=node%d user=%s proc=bash".formatted(
                        seq, baseTime.plusSeconds(seq).toString(), seq % 2, user));
    }

    /** IDS：暴力破解信号。 */
    public RawRecord ids(int seq) {
        return new RawRecord(EventSource.IDS,
                "iid=ids-%d ts=%s sig=BRUTE sensor=ids%d user=u%d".formatted(
                        seq, baseTime.plusSeconds(seq).toString(), seq % 2, seq % 5));
    }

    /** 将列表随机打乱，模拟乱序到达。 */
    public List<RawRecord> shuffled(List<RawRecord> records) {
        List<RawRecord> copy = new ArrayList<>(records);
        Collections.shuffle(copy, random);
        return copy;
    }

    /** 在列表中随机插入重复记录，模拟重复消费。 */
    public List<RawRecord> withDuplicates(List<RawRecord> records, int duplicates) {
        List<RawRecord> copy = new ArrayList<>(records);
        for (int i = 0; i < duplicates; i++) {
            copy.add(random.nextInt(copy.size() + 1),
                    records.get(random.nextInt(records.size())));
        }
        return copy;
    }
}
