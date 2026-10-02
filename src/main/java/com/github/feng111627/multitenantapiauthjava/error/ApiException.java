package com.github.feng111627.multitenantapiauthjava.error;

/**
 * 业务异常：携带错误码与 HTTP 状态。
 */
public class ApiException extends RuntimeException {

    private final ErrorCode code;
    private final int httpStatus;

    public ApiException(ErrorCode code, int httpStatus, String message) {
        super(message);
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public ErrorCode getCode() {
        return code;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
