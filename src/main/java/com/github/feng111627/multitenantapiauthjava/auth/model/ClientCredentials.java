package com.github.feng111627.multitenantapiauthjava.auth.model;

import java.util.Map;
import java.util.Set;

/**
 * 一个外部客户端的身份与访问范围配置。
 *
 * @param clientId       客户端标识
 * @param secret         HMAC 密钥（Base64 编码）
 * @param allowedScopes  允许访问的接口范围（scope 标识集合）
 * @param ownerId        数据归属标识（租户/数据所有者）
 * @param rateLimit      默认稳态速率：每个统计窗口稳定允许的最大请求数，
 *                       未单独配置配额的范围沿用它
 * @param burstLimit     默认突发上限：未单独配置的范围可一次性冲过的最大请求数；
 *                       小于 0 表示未配置，按 {@code rateLimit} 处理
 * @param burstConfigured 默认突发上限是否在配置中显式给出。{@code false} 表示
 *                       老配置（只写了 rate-limit）：默认配额须按"客户端级共享
 *                       固定窗口"计量，与按范围拆分上线前的行为逐点一致；
 *                       {@code true} 表示显式配置了突发余量：默认配额按
 *                       "客户端级共享令牌桶"计量（同样全客户端只有一份）
 * @param scopeQuotas    按接口范围单独配置的配额，key 为 scope 标识；
 *                       各范围独立计数、互不挤占，缺省的范围回落到客户端共享的默认配额
 */
public record ClientCredentials(
        String clientId,
        String secret,
        Set<String> allowedScopes,
        String ownerId,
        long rateLimit,
        long burstLimit,
        boolean burstConfigured,
        Map<String, QuotaProfile> scopeQuotas
) {
}
