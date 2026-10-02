package com.github.feng111627.multitenantapiauthjava.auth.model;

/**
 * 统一错误码。
 */
public enum ErrorCode {

    OK("OK", 200),
    MISSING_CREDENTIALS("AUTH_MISSING_CREDENTIALS", 401),
    UNKNOWN_CLIENT("AUTH_UNKNOWN_CLIENT", 401),
    INVALID_SIGNATURE("AUTH_INVALID_SIGNATURE", 401),
    TIMESTAMP_EXPIRED("AUTH_TIMESTAMP_EXPIRED", 401),
    REPLAY_DETECTED("AUTH_REPLAY_DETECTED", 409),
    ACCESS_DENIED("ACCESS_DENIED", 403),
    RATE_LIMITED("RATE_LIMITED", 429),
    PARAM_INVALID("PARAM_INVALID", 400),
    INTERNAL_ERROR("INTERNAL_ERROR", 500);

    private final String code;
    private final int httpStatus;

    ErrorCode(String code, int httpStatus) {
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public String code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
