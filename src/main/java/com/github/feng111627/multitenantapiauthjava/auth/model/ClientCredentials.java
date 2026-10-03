package com.github.feng111627.multitenantapiauthjava.auth.model;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 一个外部客户端的身份与访问范围配置。
 *
 * @param clientId       客户端标识
 * @param secret         HMAC 密钥（Base64 编码）
 * @param allowedScopes  允许访问的接口范围（scope 标识集合）
 * @param ownerId        数据归属标识（租户/数据所有者）
 * @param rateLimit      默认配额：每个统计窗口允许的最大请求数（未单独配置的 scope 沿用）
 * @param scopeQuotas    分范围配额，key 为 scope；仅对显式配置的 scope 生效
 */
public record ClientCredentials(
        String clientId,
        String secret,
        Set<String> allowedScopes,
        String ownerId,
        long rateLimit,
        Map<String, ScopeQuota> scopeQuotas
) {

    /**
     * 查询某个 scope 的独立配额；未配置时返回 empty，表示沿用默认 {@link #rateLimit}。
     *
     * <p>查找键经过与配置绑定相同的归一化（{@link #normalizeScopeName}），
     * 因此配置里写 {@code orders:read} 能匹配接口上真实的 {@code orders:read}。</p>
     */
    public Optional<ScopeQuota> quotaFor(String scope) {
        if (scope == null || scopeQuotas == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(scopeQuotas.get(normalizeScopeName(scope)));
    }

    /**
     * 归一化 scope 配置键：与 Spring relaxed binding 对 map key 的处理对齐，
     * 去掉冒号/连字符等分隔符，例如 {@code orders:read} 与绑定后的 {@code ordersread}
     * 归一化结果相同，避免 YAML/properties 配置键与接口真实 scope 名对不上。
     */
    public static String normalizeScopeName(String scope) {
        if (scope == null) {
            return "";
        }
        return scope.replace(":", "").replace("-", "").trim();
    }
}
