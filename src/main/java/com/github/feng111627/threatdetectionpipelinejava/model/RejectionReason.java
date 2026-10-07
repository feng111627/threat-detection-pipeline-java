package com.github.feng111627.threatdetectionpipelinejava.model;

/**
 * 可区分的拒绝原因（每条都能定位到具体环节与原因码）。
 */
public enum RejectionReason {

    EMPTY_PAYLOAD(RejectionCategory.PARSE, "P001", "原始报文为空"),
    UNSUPPORTED_FORMAT(RejectionCategory.PARSE, "P002", "不支持的报文格式或来源"),
    MALFORMED_JSON(RejectionCategory.PARSE, "P003", "JSON 格式非法"),
    MALFORMED_CSV(RejectionCategory.PARSE, "P004", "CSV 格式非法"),
    MALFORMED_KEYVALUE(RejectionCategory.PARSE, "P005", "键值对格式非法"),
    MISSING_TIMESTAMP(RejectionCategory.PARSE, "P006", "缺少时间戳字段"),
    MALFORMED_TIMESTAMP(RejectionCategory.PARSE, "P007", "时间戳格式非法或无法解析"),

    MISSING_SOURCE(RejectionCategory.VALIDATION, "V001", "缺少事件来源"),
    MISSING_EVENT_TYPE(RejectionCategory.VALIDATION, "V002", "缺少事件类型"),
    UNKNOWN_EVENT_TYPE(RejectionCategory.VALIDATION, "V003", "事件类型不在允许集合内"),
    MISSING_SUBJECT(RejectionCategory.VALIDATION, "V004", "主体缺失：sourceIp 与 user 不能同时为空"),
    TIMESTAMP_IN_FUTURE(RejectionCategory.VALIDATION, "V005", "事件时间超出允许的未来偏移"),
    TIMESTAMP_TOO_OLD(RejectionCategory.VALIDATION, "V006", "事件时间早于允许的最早时间"),
    DUPLICATE_EVENT(RejectionCategory.VALIDATION, "V007", "事件重复到达，已去重");

    private final RejectionCategory category;
    private final String code;
    private final String defaultMessage;

    RejectionReason(RejectionCategory category, String code, String defaultMessage) {
        this.category = category;
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    public RejectionCategory category() {
        return category;
    }

    public String code() {
        return code;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
