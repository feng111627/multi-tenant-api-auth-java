package com.github.feng111627.multitenantapiauthjava.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 鉴权相关可配置项。
 */
@ConfigurationProperties(prefix = "app.auth")
public class AuthProperties {

    /** 时间戳允许的偏差（秒），双向生效。 */
    private long timestampSkewSeconds = 300;

    /** 重放/已用 nonce 的保留时长（秒）。 */
    private long nonceTtlSeconds = 600;

    /** 限流统计窗口长度（秒）。 */
    private long rateWindowSeconds = 60;

    /** 预置客户端凭据，key 为 clientId。 */
    private Map<String, Client> clients = new LinkedHashMap<>();

    public long getTimestampSkewSeconds() {
        return timestampSkewSeconds;
    }

    public void setTimestampSkewSeconds(long timestampSkewSeconds) {
        this.timestampSkewSeconds = timestampSkewSeconds;
    }

    public long getNonceTtlSeconds() {
        return nonceTtlSeconds;
    }

    public void setNonceTtlSeconds(long nonceTtlSeconds) {
        this.nonceTtlSeconds = nonceTtlSeconds;
    }

    public long getRateWindowSeconds() {
        return rateWindowSeconds;
    }

    public void setRateWindowSeconds(long rateWindowSeconds) {
        this.rateWindowSeconds = rateWindowSeconds;
    }

    public Map<String, Client> getClients() {
        return clients;
    }

    public void setClients(Map<String, Client> clients) {
        this.clients = clients;
    }

    public static class Client {
        private String secret;
        private String owner;
        private java.util.List<String> scopes = new java.util.ArrayList<>();
        private long rateLimit = 100;
        /** 分范围配额，key 为 scope 标识；未配置的 scope 沿用 {@link #rateLimit}。 */
        private Map<String, ScopeQuota> scopeQuotas = new LinkedHashMap<>();

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public String getOwner() {
            return owner;
        }

        public void setOwner(String owner) {
            this.owner = owner;
        }

        public java.util.List<String> getScopes() {
            return scopes;
        }

        public void setScopes(java.util.List<String> scopes) {
            this.scopes = scopes;
        }

        public long getRateLimit() {
            return rateLimit;
        }

        public void setRateLimit(long rateLimit) {
            this.rateLimit = rateLimit;
        }

        public Map<String, ScopeQuota> getScopeQuotas() {
            return scopeQuotas;
        }

        public void setScopeQuotas(Map<String, ScopeQuota> scopeQuotas) {
            this.scopeQuotas = scopeQuotas;
        }
    }

    /**
     * 单个 scope 的配额配置：稳态限额 {@code rateLimit} 加突发余量 {@code burst}。
     */
    public static class ScopeQuota {
        /** 稳态限额：每个统计窗口的令牌补充量；&lt;=0 时沿用客户端默认 {@code rate-limit}。 */
        private long rateLimit = 0;
        /** 突发余量：在稳态限额之上额外允许的一次性请求数，默认 0（行为与固定窗口一致）。 */
        private long burst = 0;

        public long getRateLimit() {
            return rateLimit;
        }

        public void setRateLimit(long rateLimit) {
            this.rateLimit = rateLimit;
        }

        public long getBurst() {
            return burst;
        }

        public void setBurst(long burst) {
            this.burst = burst;
        }
    }
}
