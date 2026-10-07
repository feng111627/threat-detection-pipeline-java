package com.github.feng111627.threatdetectionpipelinejava.ingest;

import com.github.feng111627.threatdetectionpipelinejava.model.EventType;
import com.github.feng111627.threatdetectionpipelinejava.model.SecurityEvent;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 业务校验器：事件已解析成功，此处校验语义是否合法。
 * 与解析失败区分：此处抛 ValidationException，拒绝记录标记为 VALIDATE 阶段。
 */
public class EventValidator {

    private static final Pattern EVENT_ID = Pattern.compile("[A-Za-z0-9._:-]{4,128}");
    private static final Set<EventType> USER_REQUIRED =
            EnumSet.of(EventType.LOGIN_FAILED, EventType.LOGIN_SUCCESS, EventType.FILE_ACCESS);

    private final Clock clock;
    private final Duration maxFutureSkew;
    private final Duration maxPastSkew;

    public EventValidator(Clock clock, Duration maxFutureSkew, Duration maxPastSkew) {
        this.clock = clock;
        this.maxFutureSkew = maxFutureSkew;
        this.maxPastSkew = maxPastSkew;
    }

    public void validate(SecurityEvent event) throws ValidationException {
        if (!EVENT_ID.matcher(event.eventId()).matches()) {
            throw new ValidationException("事件ID不合法: " + event.eventId());
        }
        Instant now = clock.instant();
        if (event.timestamp().isAfter(now.plus(maxFutureSkew))) {
            throw new ValidationException("时间戳超出允许的未来偏移: " + event.timestamp());
        }
        if (event.timestamp().isBefore(now.minus(maxPastSkew))) {
            throw new ValidationException("时间戳过旧，超出保留窗口: " + event.timestamp());
        }
        if (event.host() == null || event.host().isBlank()) {
            throw new ValidationException("主机名为空");
        }
        if (USER_REQUIRED.contains(event.type())
                && (event.user() == null || event.user().isBlank())) {
            throw new ValidationException("事件类型 " + event.type() + " 要求用户字段非空");
        }
    }
}
