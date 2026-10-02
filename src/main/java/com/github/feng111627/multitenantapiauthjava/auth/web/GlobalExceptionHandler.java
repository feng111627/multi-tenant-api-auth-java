package com.github.feng111627.multitenantapiauthjava.auth.web;

import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorResponse;
import com.github.feng111627.multitenantapiauthjava.auth.sign.SignatureService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一异常处理：任何异常都转换为结构稳定的 {@link ErrorResponse}，
 * 底层异常信息不直接暴露给调用方。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApi(ApiException ex, HttpServletRequest request) {
        return build(ex.getErrorCode(), ex.getMessage(), request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex,
                                                         HttpServletRequest request) {
        return build(ErrorCode.PARAM_INVALID, "request body is missing or malformed", request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex,
                                                               HttpServletRequest request) {
        return build(ErrorCode.PARAM_INVALID, ex.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex, HttpServletRequest request) {
        String requestId = requestId(request);
        // 详细堆栈只留在服务端日志
        log.error("unexpected error requestId={}", requestId, ex);
        return build(ErrorCode.INTERNAL_ERROR, "internal server error", request);
    }

    private static ResponseEntity<ErrorResponse> build(ErrorCode code, String message,
                                                       HttpServletRequest request) {
        String requestId = requestId(request);
        ErrorResponse body = new ErrorResponse(code.code(), message, requestId,
                System.currentTimeMillis());
        log.info("error response requestId={} code={} message={}", requestId, code.code(), message);
        return ResponseEntity.status(code.httpStatus())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    private static String requestId(HttpServletRequest request) {
        String requestId = request.getHeader(SignatureService.HEADER_REQUEST_ID);
        return (requestId == null || requestId.isBlank()) ? "-" : requestId;
    }
}
