package com.github.feng111627.multitenantapiauthjava.error;

/**
 * 稳定的对外错误码。
 */
public enum ErrorCode {
    SIGNATURE_INVALID,
    TIMESTAMP_EXPIRED,
    NONCE_REPLAYED,
    CLIENT_UNKNOWN,
    SCOPE_FORBIDDEN,
    TENANT_FORBIDDEN,
    RATE_LIMITED,
    BAD_REQUEST,
    INTERNAL_ERROR
}
