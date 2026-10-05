package com.github.feng111627.multitenantapiauthjava.auth.config;

import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.QuotaProfile;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 客户端凭据注册表：启动时把 {@link AuthProperties} 中的配置物化为不可变注册表。
 *
 * <p>配额解析规则：每个客户端有一条默认配额（{@code rateLimit}/{@code burstLimit}），
 * 另外可按 scope 单独配置；未单独配置的 scope 在运行时回落到默认配额——默认配额
 * 整个客户端只有一份，由所有回落到它的范围共用（见
 * {@link com.github.feng111627.multitenantapiauthjava.auth.rate.QuotaService}）。
 * {@code burstLimit} 未配置（&lt; 0）时按同维度 {@code rateLimit} 归一，同时把
 * {@code burstConfigured} 置为 {@code false}，供运行时对老配置走与拆分前一致的
 * 固定窗口计量。</p>
 */
@Component
public class ClientRegistry {

    private final Map<String, ClientCredentials> clients;

    public ClientRegistry(AuthProperties properties) {
        Map<String, ClientCredentials> map = new LinkedHashMap<>();
        properties.getClients().forEach((id, cfg) -> {
            Set<String> scopes = cfg.getScopes() == null
                    ? Set.of()
                    : cfg.getScopes().stream().collect(Collectors.toUnmodifiableSet());

            Map<String, QuotaProfile> scopeQuotas = new LinkedHashMap<>();
            if (cfg.getScopeQuotas() != null) {
                for (AuthProperties.ScopeQuotaConfig quota : cfg.getScopeQuotas()) {
                    if (quota == null || quota.getScope() == null || quota.getScope().isBlank()) {
                        continue;
                    }
                    scopeQuotas.put(quota.getScope(), new QuotaProfile(
                            quota.getRateLimit(),
                            normalizeBurst(quota.getBurstLimit(), quota.getRateLimit())));
                }
            }

            map.put(id, new ClientCredentials(
                    id,
                    cfg.getSecret(),
                    scopes,
                    cfg.getOwner(),
                    cfg.getRateLimit(),
                    normalizeBurst(cfg.getBurstLimit(), cfg.getRateLimit()),
                    cfg.getBurstLimit() >= 0,
                    Map.copyOf(scopeQuotas)));
        });
        this.clients = Map.copyOf(map);
    }

    private static long normalizeBurst(long burstLimit, long rateLimit) {
        return burstLimit >= 0 ? burstLimit : rateLimit;
    }

    public Optional<ClientCredentials> find(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(clients.get(clientId));
    }
}
