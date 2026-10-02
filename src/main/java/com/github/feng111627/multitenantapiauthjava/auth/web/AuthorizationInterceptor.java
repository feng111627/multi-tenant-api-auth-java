package com.github.feng111627.multitenantapiauthjava.auth.web;

import com.github.feng111627.multitenantapiauthjava.auth.config.AuthProperties;
import com.github.feng111627.multitenantapiauthjava.auth.config.ClientRegistry;
import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientContext;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.auth.model.RequireScope;
import com.github.feng111627.multitenantapiauthjava.auth.rate.ClientRateLimiter;
import com.github.feng111627.multitenantapiauthjava.auth.sign.SignatureService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 鉴权与访问控制拦截器。
 *
 * <p>处理顺序（每一步拒绝原因都可区分）：</p>
 * <ol>
 *     <li>四个鉴权头必须齐全；</li>
 *     <li>clientId 必须在注册表中；</li>
 *     <li>按客户端维度限流（限流先于验签，被限流的请求不会消耗 nonce）；</li>
 *     <li>时间戳窗口、签名、重放检测（见 {@link SignatureService}）；</li>
 *     <li>接口 scope 校验。</li>
 * </ol>
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final ClientRegistry clientRegistry;
    private final SignatureService signatureService;
    private final ClientRateLimiter rateLimiter;
    private final AuthProperties properties;

    public AuthorizationInterceptor(ClientRegistry clientRegistry,
                                    SignatureService signatureService,
                                    ClientRateLimiter rateLimiter,
                                    AuthProperties properties) {
        this.clientRegistry = clientRegistry;
        this.signatureService = signatureService;
        this.rateLimiter = rateLimiter;
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) {
        String requestId = requestId(request);

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        String clientId = request.getHeader(SignatureService.HEADER_CLIENT_ID);
        String timestamp = request.getHeader(SignatureService.HEADER_TIMESTAMP);
        String nonce = request.getHeader(SignatureService.HEADER_NONCE);
        String signature = request.getHeader(SignatureService.HEADER_SIGNATURE);

        if (isBlank(clientId) || isBlank(timestamp) || isBlank(nonce) || isBlank(signature)) {
            reject(requestId, clientId, ErrorCode.MISSING_CREDENTIALS,
                    "one or more auth headers are missing");
        }

        ClientCredentials client = clientRegistry.find(clientId)
                .orElseGet(() -> {
                    reject(requestId, clientId, ErrorCode.UNKNOWN_CLIENT,
                            "client is not registered");
                    return null;
                });

        long windowMillis = properties.getRateWindowSeconds() * 1000L;
        boolean allowed = rateLimiter.tryAcquire(client.clientId(), client.rateLimit(), windowMillis);
        if (!allowed) {
            reject(requestId, client.clientId(), ErrorCode.RATE_LIMITED,
                    "rate limit " + client.rateLimit() + " per "
                            + properties.getRateWindowSeconds() + "s exceeded");
        }

        signatureService.verify(request, client);

        RequireScope required = handlerMethod.getMethodAnnotation(RequireScope.class);
        if (required == null) {
            required = handlerMethod.getBeanType().getAnnotation(RequireScope.class);
        }
        if (required != null && !client.allowedScopes().contains(required.value())) {
            reject(requestId, client.clientId(), ErrorCode.ACCESS_DENIED,
                    "scope '" + required.value() + "' is not granted");
        }

        ClientContext.set(client);
        log.info("access granted clientId={} requestId={} owner={} scope={}",
                client.clientId(), requestId, client.ownerId(),
                required == null ? "-" : required.value());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        // 必须清理：线程池复用线程，避免下一个请求串到上一个客户端的身份
        ClientContext.clear();
    }

    private static String requestId(HttpServletRequest request) {
        String requestId = request.getHeader(SignatureService.HEADER_REQUEST_ID);
        return (requestId == null || requestId.isBlank()) ? "-" : requestId;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static void reject(String requestId, String clientId, ErrorCode code, String reason) {
        log.warn("access rejected clientId={} requestId={} code={} reason={}",
                clientId == null ? "-" : clientId, requestId, code.code(), reason);
        throw new ApiException(code, reason);
    }
}
