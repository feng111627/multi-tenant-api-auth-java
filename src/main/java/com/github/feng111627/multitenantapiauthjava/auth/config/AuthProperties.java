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
        /** 默认突发上限；小于 0 表示未配置，运行时按 rateLimit 处理。 */
        private long burstLimit = -1;
        /** 按接口范围单独配置的配额，缺省的范围沿用默认 rateLimit/burstLimit。 */
        private java.util.List<ScopeQuotaConfig> scopeQuotas = new java.util.ArrayList<>();

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

        public long getBurstLimit() {
            return burstLimit;
        }

        public void setBurstLimit(long burstLimit) {
            this.burstLimit = burstLimit;
        }

        public java.util.List<ScopeQuotaConfig> getScopeQuotas() {
            return scopeQuotas;
        }

        public void setScopeQuotas(java.util.List<ScopeQuotaConfig> scopeQuotas) {
            this.scopeQuotas = scopeQuotas;
        }
    }

    /**
     * 单个接口范围的配额配置。
     */
    public static class ScopeQuotaConfig {
        private String scope;
        private long rateLimit;
        /** 突发上限；小于 0 表示未配置，运行时按该范围 rateLimit 处理。 */
        private long burstLimit = -1;

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public long getRateLimit() {
            return rateLimit;
        }

        public void setRateLimit(long rateLimit) {
            this.rateLimit = rateLimit;
        }

        public long getBurstLimit() {
            return burstLimit;
        }

        public void setBurstLimit(long burstLimit) {
            this.burstLimit = burstLimit;
        }
    }
}
