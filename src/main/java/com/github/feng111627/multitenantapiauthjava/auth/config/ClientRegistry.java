package com.github.feng111627.multitenantapiauthjava.auth.config;

import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ScopeQuota;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 客户端凭据注册表：启动时把 {@link AuthProperties} 中的配置物化为不可变注册表。
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

            Map<String, ScopeQuota> scopeQuotas = new LinkedHashMap<>();
            if (cfg.getScopeQuotas() != null) {
                cfg.getScopeQuotas().forEach((rawScopeName, q) -> {
                    if (rawScopeName != null && !rawScopeName.isBlank()) {
                        long effectiveRate = q.getRateLimit() > 0
                                ? q.getRateLimit()
                                : cfg.getRateLimit();
                        long burst = Math.max(0, q.getBurst());
                        // Spring relaxed binding 会把 key 中的 ':'/'-' 等剥掉，
                        // 因此配置键与真实 scope 名都做同一归一化后再建表/查找
                        scopeQuotas.put(ClientCredentials.normalizeScopeName(rawScopeName),
                                new ScopeQuota(rawScopeName, effectiveRate, burst));
                    }
                });
            }

            map.put(id, new ClientCredentials(
                    id,
                    cfg.getSecret(),
                    scopes,
                    cfg.getOwner(),
                    cfg.getRateLimit(),
                    Map.copyOf(scopeQuotas)));
        });
        this.clients = Map.copyOf(map);
    }

    public Optional<ClientCredentials> find(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(clients.get(clientId));
    }
}
