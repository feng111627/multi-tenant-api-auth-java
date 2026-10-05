package com.github.feng111627.multitenantapiauthjava.auth.web;

import com.github.feng111627.multitenantapiauthjava.auth.config.AuthProperties;
import com.github.feng111627.multitenantapiauthjava.auth.config.ClientRegistry;
import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientContext;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.auth.model.QuotaProfile;
import com.github.feng111627.multitenantapiauthjava.auth.model.RequireScope;
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
 *     <li>配额判定：单独配置过配额的范围走独立的「客户端 × 范围」令牌桶；
 *         未单独配置的范围共用客户端级默认额度（老配置为固定窗口，
 *         显式配置了突发余量的为令牌桶）。</li>
 * </ol>
 *
 * <p><b>配额放在验签与 scope 校验之后</b>：任何未通过身份/签名/范围校验的请求都在
 * 占用名额之前被拒绝，因此外部攻击者即便知道 clientId 并伪造大量请求，也无法消耗
 * 该客户端真正可用的配额，更不会被算到别的客户端头上（桶键以服务端确认过的
 * clientId 与接口 scope 组合）。</p>
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final ClientRegistry clientRegistry;
    private final SignatureService signatureService;
    private final QuotaService quotaService;
    private final AuthProperties properties;

    public AuthorizationInterceptor(ClientRegistry clientRegistry,
                                    SignatureService signatureService,
                                    QuotaService quotaService,
                                    AuthProperties properties) {
        this.clientRegistry = clientRegistry;
        this.signatureService = signatureService;
        this.quotaService = quotaService;
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
            reject(requestId, clientId, QuotaService.DEFAULT_SCOPE,
                    ErrorCode.MISSING_CREDENTIALS, "one or more auth headers are missing");
        }

        ClientCredentials client = clientRegistry.find(clientId)
                .orElseGet(() -> {
                    reject(requestId, clientId, QuotaService.DEFAULT_SCOPE,
                            ErrorCode.UNKNOWN_CLIENT, "client is not registered");
                    return null;
                });

        // 先验签（含时间戳/重放）：未通过校验的请求不占用任何配额
        signatureService.verify(request, client);

        RequireScope required = handlerMethod.getMethodAnnotation(RequireScope.class);
        if (required == null) {
            required = handlerMethod.getBeanType().getAnnotation(RequireScope.class);
        }
        String scope = required == null ? QuotaService.DEFAULT_SCOPE : required.value();

        if (required != null && !client.allowedScopes().contains(required.value())) {
            // scope 越权同样在占名额之前拒绝，不消耗任何配额桶
            reject(requestId, client.clientId(), scope, ErrorCode.ACCESS_DENIED,
                    "scope '" + required.value() + "' is not granted");
        }

        long windowMillis = properties.getRateWindowSeconds() * 1000L;
        QuotaProfile scoped = client.scopeQuotas().get(scope);
        boolean allowed;
        String quotaDesc;
        if (scoped != null) {
            // 该范围单独配置过配额：独立的 (clientId, scope) 令牌桶，各范围各算各的账
            allowed = quotaService.tryAcquire(client.clientId(), scope,
                    scoped.rateLimit(), scoped.burstLimit(), windowMillis);
            quotaDesc = "scope quota rate=" + scoped.rateLimit()
                    + " burst=" + scoped.burstLimit();
        } else if (client.defaultBurstConfigured()) {
            // 默认配额 + 显式突发：整个客户端共用同一个默认令牌桶（跨范围合计受同一份额度约束）
            allowed = quotaService.tryAcquire(client.clientId(), QuotaService.DEFAULT_SCOPE,
                    client.rateLimit(), client.burstLimit(), windowMillis);
            quotaDesc = "shared default bucket rate=" + client.rateLimit()
                    + " burst=" + client.burstLimit();
        } else {
            // 老配置（只配 rate-limit）：整个客户端共用同一个固定窗口，行为与拆分前一致
            allowed = quotaService.tryAcquireFixedWindow(client.clientId(),
                    QuotaService.DEFAULT_SCOPE, client.rateLimit(), windowMillis);
            quotaDesc = "shared default fixed-window limit=" + client.rateLimit();
        }
        if (!allowed) {
            log.warn("quota exhausted clientId={} scope={} requestId={} {} window={}s",
                    client.clientId(), scope, requestId, quotaDesc,
                    properties.getRateWindowSeconds());
            reject(requestId, client.clientId(), scope, ErrorCode.RATE_LIMITED,
                    "rate limit exceeded for scope '" + scope + "' ("
                            + quotaDesc + ", window "
                            + properties.getRateWindowSeconds() + "s)");
        }

        ClientContext.set(client);
        log.info("access granted clientId={} requestId={} owner={} scope={}",
                client.clientId(), requestId, client.ownerId(), scope);
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
        log.warn("access rejected clientId={} scope={} requestId={} code={} reason={}",
                clientId == null ? "-" : clientId, scope, requestId, code.code(), reason);
        throw new ApiException(code, reason);
    }
}
