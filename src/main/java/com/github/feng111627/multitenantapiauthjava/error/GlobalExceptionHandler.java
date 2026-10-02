package com.github.feng111627.multitenantapiauthjava.error;

import com.github.feng111627.multitenantapiauthjava.auth.AuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * 全局异常处理：把鉴权失败、参数错误、内部异常统一成稳定的错误结果，
 * 不向调用方泄露底层异常细节。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApiException(ApiException ex, HttpServletRequest request) {
        return build(ex.getCode(), ex.getHttpStatus(), ex.getMessage(), request);
    }

    @ExceptionHandler({
            MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class,
            HttpMessageNotReadableException.class,
            IllegalArgumentException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception ex, HttpServletRequest request) {
        return build(ErrorCode.BAD_REQUEST, 400, "invalid request: " + ex.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex, HttpServletRequest request) {
        log.error("internal error, requestId={}", requestId(request), ex);
        return build(ErrorCode.INTERNAL_ERROR, 500, "internal error", request);
    }

    private ResponseEntity<ErrorResponse> build(ErrorCode code, int status, String message, HttpServletRequest request) {
        ErrorResponse body = new ErrorResponse(code.name(), message, requestId(request));
        return ResponseEntity.status(status).body(body);
    }

    private String requestId(HttpServletRequest request) {
        Object attr = request.getAttribute(AuthInterceptor.REQUEST_ID_ATTR);
        return attr == null ? "unknown" : attr.toString();
    }
}
