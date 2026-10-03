package com.github.feng111627.multitenantapiauthjava.auth.model;

/**
 * 单个接口范围（scope）上的配额配置（骨架，待填充）。
 */
public record ScopeQuota(
        String scope,
        long rateLimit,
        long burst
) {
}
