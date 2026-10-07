package com.github.feng111627.threatdetectionpipelinejava.alert;

import com.github.feng111627.threatdetectionpipelinejava.engine.AlertSeed;
import com.github.feng111627.threatdetectionpipelinejava.model.Alert;
import com.github.feng111627.threatdetectionpipelinejava.model.AlertStatus;
import com.github.feng111627.threatdetectionpipelinejava.model.AlertTransition;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 告警服务：去重落库、按事件链合并、合法状态流转并记录可追溯历史。
 *
 * <p>并发语义：同 correlationKey 的落库/合并在同一把锁上串行化，
 * 保证并发接入时同一事件链最终只有一条主告警，数量与状态一致。
 */
@Service
public class AlertService {

    /** 合法状态流转表。MERGED 是终态，不允许任何后续流转。 */
    private static final Map<AlertStatus, Set<AlertStatus>> ALLOWED_TRANSITIONS;

    static {
        Map<AlertStatus, Set<AlertStatus>> map = new EnumMap<>(AlertStatus.class);
        map.put(AlertStatus.NEW, Set.of(AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.MERGED));
        map.put(AlertStatus.ACKNOWLEDGED, Set.of(AlertStatus.RESOLVED, AlertStatus.MERGED));
        map.put(AlertStatus.RESOLVED, Set.of(AlertStatus.ACKNOWLEDGED, AlertStatus.MERGED));
        map.put(AlertStatus.MERGED, Set.of());
        ALLOWED_TRANSITIONS = Map.copyOf(map);
    }

    private final AlertStore store;
    private final Clock clock;
    private final Object mergeLock = new Object();

    public AlertService(AlertStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /**
     * 幂等接收告警种子：
 * <ul>
     *   <li>同一 correlationKey 已存在告警 -> 不新增，只把新事件并入主告警（事件链合并）；</li>
     *   <li>否则创建 NEW 告警并记录创建审计。</li>
     * </ul>
     */
    public Alert ingestSeed(AlertSeed seed) {
        synchronized (mergeLock) {
            Alert existing = store.findByCorrelationKey(seed.correlationKey()).orElse(null);
            if (existing != null) {
                int added = existing.appendEventIds(seed.eventIds());
                existing.putEvidence("lastSupplementedEventCount", added);
                existing.putEvidence("lastSupplementedAt", Instant.now(clock).toString());
                existing.addTransition(new AlertTransition(Instant.now(clock), existing.status(),
                        existing.status(), "system",
                        added > 0 ? "同事件链补充 " + added + " 个事件" : "重复消费命中，告警保持不变"));
                return store.put(existing);
            }

            AlertTransition created = new AlertTransition(Instant.now(clock), null,
                    AlertStatus.NEW, "system", "规则 " + seed.ruleId()
                    + "@" + seed.ruleVersion() + " 触发，告警创建");
            Alert alert = new Alert(
                    alertId(seed),
                    seed.ruleId(),
                    seed.ruleVersion(),
                    seed.correlationKey(),
                    seed.severity(),
                    seed.title(),
                    seed.firstEventTime(),
                    seed.triggerTime(),
                    new ArrayList<>(seed.eventIds()),
                    seed.evidence(),
                    AlertStatus.NEW,
                    new ArrayList<>(List.of(created)));
            store.putIfAbsent(alert);
            return store.findByCorrelationKey(seed.correlationKey()).orElse(alert);
        }
    }

    public Alert acknowledge(String alertId, String operator, String reason) {
        return transition(alertId, AlertStatus.ACKNOWLEDGED, operator, reason);
    }

    public Alert resolve(String alertId, String operator, String reason) {
        return transition(alertId, AlertStatus.RESOLVED, operator, reason);
    }

    /** RESOLVED -> ACKNOWLEDGED：事件链上出现新证据时重开。 */
    public Alert reopen(String alertId, String operator, String reason) {
        return transition(alertId, AlertStatus.ACKNOWLEDGED, operator, reason);
    }

    /**
     * 合法状态流转；非法流转抛 {@link IllegalAlertTransitionException}。
     */
    public Alert transition(String alertId, AlertStatus target, String operator, String reason) {
        synchronized (mergeLock) {
            Alert alert = requireAlert(alertId);
            AlertStatus from = alert.status();
            if (!ALLOWED_TRANSITIONS.getOrDefault(from, Set.of()).contains(target)) {
                throw new IllegalAlertTransitionException(alertId, from, target);
            }
            alert.setStatus(target);
            alert.addTransition(new AlertTransition(Instant.now(clock), from, target,
                    operator == null ? "anonymous" : operator, reason));
            return store.put(alert);
        }
    }

    /**
     * 将同规则下的子告警合并到父告警：子告警进入 MERGED 终态并记录指向，
     * 父告警吸收事件链证据并按状态机允许度推进。两条告警必须来自同一条规则。
     */
    public Alert merge(String childAlertId, String parentAlertId, String operator) {
        if (childAlertId.equals(parentAlertId)) {
            throw new IllegalArgumentException("不能将告警合并到自身");
        }
        synchronized (mergeLock) {
            Alert child = requireAlert(childAlertId);
            Alert parent = requireAlert(parentAlertId);
            if (!child.ruleId().equals(parent.ruleId())) {
                throw new IllegalArgumentException("仅允许合并同一规则下的告警: "
                        + child.ruleId() + " vs " + parent.ruleId());
            }
            if (child.status() == AlertStatus.MERGED) {
                throw new IllegalAlertTransitionException(childAlertId, AlertStatus.MERGED, AlertStatus.MERGED);
            }

            int added = parent.appendEventIds(child.eventIds());
            parent.putEvidence("merged:" + child.alertId(),
                    Map.of("severity", child.severity().name(),
                            "correlationKey", child.correlationKey(),
                            "addedEventCount", added,
                            "ruleVersion", child.ruleVersion()));
            parent.addTransition(new AlertTransition(Instant.now(clock), parent.status(),
                    parent.status(), operator == null ? "system" : operator,
                    "合并告警 " + child.alertId() + "，吸收 " + added + " 个新事件"));

            AlertStatus childFrom = child.status();
            child.setMergedInto(parent.alertId());
            child.setStatus(AlertStatus.MERGED);
            child.addTransition(new AlertTransition(Instant.now(clock), childFrom,
                    AlertStatus.MERGED, operator == null ? "system" : operator,
                    "合并进主告警 " + parent.alertId()));

            store.put(parent);
            store.put(child);
            return parent;
        }
    }

    public void clear() {
        synchronized (mergeLock) {
            store.clear();
        }
    }

    public Alert findByCorrelationKey(String correlationKey) {
        return store.findByCorrelationKey(correlationKey).orElse(null);
    }

    public List<Alert> allAlerts() {
        return store.findAll();
    }

    private Alert requireAlert(String alertId) {
        return store.findById(alertId)
                .orElseThrow(() -> new IllegalArgumentException("告警不存在: " + alertId));
    }

    /** 告警 ID 由 correlationKey 决定，天然幂等，且可从输入复现。 */
    private static String alertId(AlertSeed seed) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(seed.correlationKey().getBytes(StandardCharsets.UTF_8));
            return "alert-" + HexFormat.of().formatHex(digest, 0, 8);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
