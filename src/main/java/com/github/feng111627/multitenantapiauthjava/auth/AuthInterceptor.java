package com.github.feng111627.multitenantapiauthjava.auth;

import com.github.feng111627.multitenantapiauthjava.error.ApiException;
import com.github.feng111627.multitenantapiauthjava.error.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.ratelimit.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 鉴权拦截器，按顺序执行以下检查，任一失败即以可区分的错误码拒绝：
 *
 * 1. 客户端身份（X-Client-Id 必须已注册）      -> CLIENT_UNKNOWN
 * 2. 时间戳偏差（X-Timestamp 在容忍窗口内）     -> TIMESTAMP_EXPIRED
 * 3. 签名校验（HMAC-SHA256，X-Signature）       -> SIGNATURE_INVALID
 * 4. 重放检测（X-Nonce 在 TTL 内唯一）          -> NONCE_REPLAYED
 * 5. 频率限制（按客户端令牌桶）                 -> RATE_LIMITED
 * 6. 接口范围（路径必须在客户端允许列表内）     -> SCOPE_FORBIDDEN
 *
 * 全部通过后把客户端身份写入 {@link ClientContext}，请求结束时清理。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String HEADER_CLIENT_ID = "X-Client-Id";
    public static final String HEADER_TIMESTAMP = "X-Timestamp";
    public static final String HEADER_NONCE = "X-Nonce";
    public static final String HEADER_SIGNATURE = "X-Signature";
    public static final String REQUEST_ID_ATTR = AuthInterceptor.class.getName() + ".REQUEST_ID";

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptor.class);

    private final ClientRegistry clientRegistry;
    private final NonceStore nonceStore;
    private final RateLimiter rateLimiter;
    private final long timestampToleranceMillis;

    public AuthInterceptor(ClientRegistry clientRegistry,
                           NonceStore nonceStore,
                           RateLimiter rateLimiter,
                           @Value("${auth.timestamp-tolerance-millis:300000}") long timestampToleranceMillis) {
        this.clientRegistry = clientRegistry;
        this.nonceStore = nonceStore;
        this.rateLimiter = rateLimiter;
        this.timestampToleranceMillis = timestampToleranceMillis;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String clientId = request.getHeader(HEADER_CLIENT_ID);
        String timestamp = request.getHeader(HEADER_TIMESTAMP);
        String nonce = request.getHeader(HEADER_NONCE);
        String signature = request.getHeader(HEADER_SIGNATURE);
        String requestId = nonce == null || nonce.isBlank() ? "unknown" : clientId + ":" + nonce;
        request.setAttribute(REQUEST_ID_ATTR, requestId);

        ApiClient client = clientRegistry.findById(clientId)
                .orElseThrow(() -> reject(requestId, ErrorCode.CLIENT_UNKNOWN, 401,
                        "unknown client: " + clientId));

        checkTimestamp(requestId, timestamp);

        String canonical = SignatureUtils.buildCanonicalString(
                request.getMethod(), request.getRequestURI(), timestamp, nonce,
                CachedBodyFilter.cachedBody(request));
        String expected = SignatureUtils.sign(client.secret(), canonical);
        if (!SignatureUtils.signatureEquals(expected, signature)) {
            throw reject(requestId, ErrorCode.SIGNATURE_INVALID, 401, "signature mismatch");
        }

        if (!nonceStore.markIfAbsent(clientId, nonce)) {
            throw reject(requestId, ErrorCode.NONCE_REPLAYED, 401, "duplicated nonce");
        }

        if (!rateLimiter.tryAcquire(clientId)) {
            throw reject(requestId, ErrorCode.RATE_LIMITED, 429, "rate limit exceeded");
        }

        if (!clientRegistry.isPathAllowed(client, request.getRequestURI())) {
            throw reject(requestId, ErrorCode.SCOPE_FORBIDDEN, 403,
                    "path not allowed: " + request.getRequestURI());
        }

        ClientContext.set(client);
        log.info("auth passed, requestId={}, clientId={}, path={}", requestId, clientId, request.getRequestURI());
        return true;
    }

    private void checkTimestamp(String requestId, String timestamp) {
        long ts;
        try {
            ts = Long.parseLong(timestamp == null ? "" : timestamp.trim());
        } catch (NumberFormatException e) {
            throw reject(requestId, ErrorCode.TIMESTAMP_EXPIRED, 401, "malformed timestamp");
        }
        long skew = Math.abs(System.currentTimeMillis() - ts);
        if (skew > timestampToleranceMillis) {
            throw reject(requestId, ErrorCode.TIMESTAMP_EXPIRED, 401,
                    "timestamp skew " + skew + "ms exceeds tolerance " + timestampToleranceMillis + "ms");
        }
    }

    private ApiException reject(String requestId, ErrorCode code, int status, String detail) {
        log.warn("auth rejected, requestId={}, code={}, reason={}", requestId, code, detail);
        return new ApiException(code, status, detail);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        ClientContext.clear();
    }
}
