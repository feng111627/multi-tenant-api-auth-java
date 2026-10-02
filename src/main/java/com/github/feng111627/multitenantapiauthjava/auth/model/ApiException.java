package com.github.feng111627.multitenantapiauthjava.auth.model;

/**
 * 业务可识别异常，由全局异常处理器统一转换为标准错误结果。
 */
public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
