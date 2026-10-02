package com.github.feng111627.multitenantapiauthjava.auth.config;

import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
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
            map.put(id, new ClientCredentials(
                    id,
                    cfg.getSecret(),
                    scopes,
                    cfg.getOwner(),
                    cfg.getRateLimit()));
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
