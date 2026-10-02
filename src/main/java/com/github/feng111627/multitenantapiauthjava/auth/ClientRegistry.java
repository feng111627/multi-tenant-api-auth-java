package com.github.feng111627.multitenantapiauthjava.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 客户端注册表：从配置项 auth.clients 加载客户端，按 clientId 查询。
 *
 * 配置示例：
 *   auth.clients[0].client-id=demo-client
 *   auth.clients[0].secret=change-me
 *   auth.clients[0].tenant-id=tenant-a
 *   auth.clients[0].allowed-paths=/api/orders,/api/orders/**
 */
@Component
@ConfigurationProperties(prefix = "auth")
public class ClientRegistry {

    private List<ApiClient> clients = new ArrayList<>();

    private volatile Map<String, ApiClient> index = Map.of();

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public void setClients(List<ApiClient> clients) {
        this.clients = clients == null ? List.of() : clients;
        this.index = this.clients.stream()
                .collect(Collectors.toUnmodifiableMap(ApiClient::clientId, Function.identity()));
    }

    public List<ApiClient> getClients() {
        return clients;
    }

    public Optional<ApiClient> findById(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(index.get(clientId));
    }

    /**
     * 判断客户端是否被允许访问指定路径（支持 Ant 风格通配符）。
     */
    public boolean isPathAllowed(ApiClient client, String path) {
        if (client == null || path == null) {
            return false;
        }
        return client.allowedPaths().stream().anyMatch(p -> pathMatcher.match(p, path));
    }
}
