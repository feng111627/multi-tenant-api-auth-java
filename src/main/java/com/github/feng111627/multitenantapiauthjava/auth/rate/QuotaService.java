package com.github.feng111627.multitenantapiauthjava.auth.rate;

import com.github.feng111627.multitenantapiauthjava.auth.config.AuthProperties;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ScopeQuota;
import org.springframework.stereotype.Service;

/**
 * 配额门面：决定一次请求记到哪个桶上。
 *
 * <p>规则：</p>
 * <ul>
 *     <li>客户端的某个 scope 显式配置了独立配额（含稳态额度与突发余量）：
 *     走 {@link ScopeTokenBucketLimiter}，该 scope 独立记账，与其它范围互不挤占；</li>
 *     <li>未单独配置的 scope，以及没有 {@code @RequireScope} 的接口：
 *     沿用客户端默认 {@code rate-limit}，走原来的 {@link ClientRateLimiter} 固定窗口，
 *     行为与旧版本完全一致。</li>
 * </ul>
 *
 * <p>默认桶按 clientId 记账；分范围桶按 (clientId, scope) 记账，两套键空间互不相干，
 * 不同 scope 的计数不会串。</p>
 */
@Service
public class QuotaService {

    private final AuthProperties properties;
    private final ClientRateLimiter fixedWindowLimiter;
    private final ScopeTokenBucketLimiter tokenBucketLimiter;

    public QuotaService(AuthProperties properties,
                        ClientRateLimiter fixedWindowLimiter,
                        ScopeTokenBucketLimiter tokenBucketLimiter) {
        this.properties = properties;
        this.fixedWindowLimiter = fixedWindowLimiter;
        this.tokenBucketLimiter = tokenBucketLimiter;
    }

    /**
     * 为已通过鉴权的请求占用一个配额名额。
     *
     * @param client 已验明身份的客户端（调用方必须保证只有合法请求才会走到这里）
     * @param scope  接口要求的范围；无 {@code @RequireScope} 时为 null
     */
    public QuotaDecision tryAcquire(ClientCredentials client, String scope) {
        long windowMillis = properties.getRateWindowSeconds() * 1000L;

        ScopeQuota quota = client.quotaFor(scope).orElse(null);
        if (quota != null) {
            return tokenBucketLimiter.tryAcquire(client.clientId(), scope,
                    quota.rateLimit(), quota.burst(), windowMillis);
        }

        QuotaDecision decision = fixedWindowLimiter.tryAcquireDecision(
                client.clientId(), client.rateLimit(), windowMillis);
        return new QuotaDecision(decision.allowed(), decision.remaining(),
                scope, QuotaDecision.BUCKET_DEFAULT, client.rateLimit(), 0);
    }
}
