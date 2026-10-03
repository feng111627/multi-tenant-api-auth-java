package com.github.feng111627.multitenantapiauthjava.auth.web;

import com.github.feng111627.multitenantapiauthjava.auth.config.ClientRegistry;
import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientContext;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.auth.model.RequireScope;
import com.github.feng111627.multitenantapiauthjava.auth.rate.QuotaDecision;
import com.github.feng111627.multitenantapiauthjava.auth.rate.QuotaService;
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
 *     <li>时间戳窗口、签名、重放检测（见 {@link SignatureService}）；</li>
 *     <li>接口 scope 校验；</li>
 *     <li>配额占用：只有身份合法、签名通过且具有该 scope 的请求才记账，
 *     因此伪造/未知客户端等未通过校验的请求既占不到该客户端的额度，
 *     也不会被算到别的客户端身上。</li>
 * </ol>
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final ClientRegistry clientRegistry;
    private final SignatureService signatureService;
    private final QuotaService quotaService;

    public AuthorizationInterceptor(ClientRegistry clientRegistry,
                                    SignatureService signatureService,
                                    QuotaService quotaService) {
        this.clientRegistry = clientRegistry;
        this.signatureService = signatureService;
        this.quotaService = quotaService;
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
            reject(requestId, clientId, null, ErrorCode.MISSING_CREDENTIALS,
                    "one or more auth headers are missing");
        }

        ClientCredentials client = clientRegistry.find(clientId)
                .orElseGet(() -> {
                    reject(requestId, clientId, null, ErrorCode.UNKNOWN_CLIENT,
                            "client is not registered");
                    return null;
                });

        // 先验签/重放：未通过校验的请求不进入配额统计
        signatureService.verify(request, client);

        RequireScope required = handlerMethod.getMethodAnnotation(RequireScope.class);
        if (required == null) {
            required = handlerMethod.getBeanType().getAnnotation(RequireScope.class);
        }
        String scope = required == null ? null : required.value();
        if (required != null && !client.allowedScopes().contains(scope)) {
            reject(requestId, client.clientId(), scope, ErrorCode.ACCESS_DENIED,
                    "scope '" + scope + "' is not granted");
        }

        // 鉴权全部通过后才按"客户端 + 范围"记账
        QuotaDecision decision = quotaService.tryAcquire(client, scope);
        if (!decision.allowed()) {
            reject(requestId, client.clientId(), scope, ErrorCode.RATE_LIMITED,
                    "rate limit exceeded for scope '" + decision.scopeLabel()
                            + "' (bucket=" + decision.bucketType()
                            + ", rate=" + decision.rateLimit() + ", burst=" + decision.burst() + ")");
        }

        ClientContext.set(client);
        log.info("access granted clientId={} requestId={} owner={} scope={} bucket={} remaining={}",
                client.clientId(), requestId, client.ownerId(),
                decision.scopeLabel(), decision.bucketType(), decision.remaining());
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

    private static void reject(String requestId, String clientId, String scope,
                               ErrorCode code, String reason) {
        log.warn("access rejected clientId={} requestId={} scope={} code={} reason={}",
                clientId == null ? "-" : clientId,
                requestId,
                scope == null ? "-" : scope,
                code.code(), reason);
        throw new ApiException(code, reason);
    }
}
