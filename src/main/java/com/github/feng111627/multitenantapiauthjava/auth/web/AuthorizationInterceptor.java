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
 *     <li>按「客户端 × 本次接口范围」维度做配额（令牌桶）判定。</li>
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

        QuotaProfile quota = resolveQuota(client, scope);
        long windowMillis = properties.getRateWindowSeconds() * 1000L;
        boolean allowed = tryAcquireQuota(client, scope, quota, windowMillis);
        if (!allowed) {
            log.warn("quota exhausted clientId={} scope={} requestId={} rate={} burst={} window={}s sharedDefault={}",
                    client.clientId(), scope, requestId,
                    quota.rateLimit(), quota.burstLimit(), properties.getRateWindowSeconds(),
                    isSharedDefault(client, scope));
            reject(requestId, client.clientId(), scope, ErrorCode.RATE_LIMITED,
                    "rate limit " + quota.rateLimit() + " per "
                            + properties.getRateWindowSeconds() + "s exceeded for scope '"
                            + scope + "' (burst " + quota.burstLimit() + ")");
        }

        ClientContext.set(client);
        log.info("access granted clientId={} requestId={} owner={} scope={}",
                client.clientId(), requestId, client.ownerId(), scope);
        return true;
    }

    /**
     * 解析本次请求所在范围的有效配额：该范围单独配置过就用独立配额，
     * 否则回落到客户端默认配额。注册表物化时已对 burstLimit 做过归一。
     */
    private static QuotaProfile resolveQuota(ClientCredentials client, String scope) {
        QuotaProfile scoped = client.scopeQuotas().get(scope);
        if (scoped != null) {
            return scoped;
        }
        return new QuotaProfile(client.rateLimit(), client.burstLimit());
    }

    /** 本次请求是否落在"客户端共享默认配额"上（该范围没有单独配置配额）。 */
    private static boolean isSharedDefault(ClientCredentials client, String scope) {
        return !client.scopeQuotas().containsKey(scope);
    }

    /**
     * 按配额来源选择计量方式：
     * <ul>
     *     <li>范围单独配置了配额 → 该范围自己的令牌桶，各范围各算各的账、互不挤占；</li>
     *     <li>回落默认配额且显式配置了突发余量 → 客户端级共享令牌桶
     *         （{@link QuotaService#SHARED_DEFAULT_SCOPE}），所有回落范围共用一份额度；</li>
     *     <li>回落默认配额且没配突发余量（老配置）→ 客户端级共享固定窗口，
     *         每窗口严格 {@code rateLimit} 个，窗口切换行为与按范围拆分上线前完全一致。</li>
     * </ul>
     * 后两种都以客户端为唯一键，因此被授予多个范围、但都没单独配额的老客户端，
     * 跨范围合计也只有一份默认额度，不会被放大。
     */
    private boolean tryAcquireQuota(ClientCredentials client, String scope,
                                    QuotaProfile quota, long windowMillis) {
        if (!isSharedDefault(client, scope)) {
            return quotaService.tryAcquire(client.clientId(), scope,
                    quota.rateLimit(), quota.burstLimit(), windowMillis);
        }
        if (client.burstConfigured()) {
            return quotaService.tryAcquire(client.clientId(), QuotaService.SHARED_DEFAULT_SCOPE,
                    quota.rateLimit(), quota.burstLimit(), windowMillis);
        }
        return quotaService.tryAcquireSharedFixedWindow(
                client.clientId(), quota.rateLimit(), windowMillis);
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
