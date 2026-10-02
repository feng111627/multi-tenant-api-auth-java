package com.github.feng111627.multitenantapiauthjava.auth.model;

/**
 * 统一错误响应体。
 */
public record ErrorResponse(
        String code,
        String message,
        String requestId,
        long timestamp
) {
}
