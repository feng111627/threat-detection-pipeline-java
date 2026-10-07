package com.github.feng111627.threatdetectionpipelinejava.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.threatdetectionpipelinejava.model.Severity;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 基于 Jackson 的本地规则加载器，从 classpath JSON 读取规则定义。
 */
@Component
public class JsonRuleLoader implements RuleLoader {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public RuleSet loadFromClasspath(String resource) {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalArgumentException("规则资源不存在: " + resource);
            }
            JsonNode root = objectMapper.readTree(in);
            String setVersion = root.has("version") && !root.get("version").asText().isBlank()
                    ? root.get("version").asText()
                    : "unversioned-" + Instant.now().toEpochMilli();
            JsonNode rulesNode = root.get("rules");
            if (rulesNode == null || !rulesNode.isArray()) {
                throw new IllegalArgumentException("规则文件缺少 rules 数组: " + resource);
            }
            List<DetectionRule> rules = new ArrayList<>();
            for (JsonNode node : rulesNode) {
                DetectionRule rule = parseRule(node);
                if (rule.version() == null) {
                    rule = withVersion(rule, setVersion);
                }
                rules.add(rule);
            }
            return new RuleSet(setVersion, Instant.now(), List.copyOf(rules));
        } catch (IOException e) {
            throw new IllegalArgumentException("规则文件读取失败: " + resource, e);
        }
    }

    private DetectionRule parseRule(JsonNode node) {
        Map<String, String> matchAttributes = new LinkedHashMap<>();
        JsonNode attrs = node.get("matchAttributes");
        if (attrs != null && attrs.isObject()) {
            attrs.fields().forEachRemaining(e -> matchAttributes.put(e.getKey(), e.getValue().asText()));
        }

        List<String> sequence = new ArrayList<>();
        JsonNode seq = node.get("sequence");
        if (seq != null && seq.isArray()) {
            seq.forEach(item -> sequence.add(item.asText()));
        }

        List<String> groupBy = new ArrayList<>();
        JsonNode group = node.get("groupBy");
        if (group != null && group.isArray()) {
            group.forEach(item -> groupBy.add(item.asText()));
        }

        return new DetectionRule(
                requiredText(node, "id"),
                optionalText(node, "version"),
                node.has("enabled") && node.get("enabled").asBoolean(true),
                RuleType.valueOf(requiredText(node, "type")),
                optionalText(node, "matchEventType"),
                optionalText(node, "matchSource"),
                Map.copyOf(matchAttributes),
                node.path("threshold").asInt(1),
                node.path("windowSeconds").asLong(60),
                node.path("allowedLatenessSeconds").asLong(10),
                List.copyOf(sequence),
                List.copyOf(groupBy),
                Severity.valueOf(node.path("severity").asText("MEDIUM")),
                optionalText(node, "title"));
    }

    private static DetectionRule withVersion(DetectionRule rule, String version) {
        return new DetectionRule(rule.id(), version, rule.enabled(), rule.type(),
                rule.matchEventType(), rule.matchSource(), rule.matchAttributes(),
                rule.threshold(), rule.windowSeconds(), rule.allowedLatenessSeconds(),
                rule.sequence(), rule.groupBy(), rule.severity(), rule.title());
    }

    private static String requiredText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || value.asText().isBlank()) {
            throw new IllegalArgumentException("规则缺少必填字段: " + field);
        }
        return value.asText();
    }

    private static String optionalText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() || value.asText().isBlank() ? null : value.asText();
    }
}
