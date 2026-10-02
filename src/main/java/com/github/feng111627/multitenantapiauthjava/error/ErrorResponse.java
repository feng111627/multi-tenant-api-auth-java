package com.github.feng111627.multitenantapiauthjava.error;

/**
 * 统一错误返回体。
 */
public record ErrorResponse(String code, String message, String requestId) {
}
