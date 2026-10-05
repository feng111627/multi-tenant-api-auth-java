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
 * @param rateLimit              默认稳态速率：每个统计窗口稳定允许的最大请求数，
 *                               未单独配置配额的范围共用这一份默认额度
 * @param burstLimit             默认突发上限：未单独配置的范围可一次性冲过的最大请求数；
 *                               注册表物化时已归一（未配置时等于 {@code rateLimit}）
 * @param defaultBurstConfigured 默认突发上限是否被显式配置过。老配置（只配
 *                               {@code rate-limit}）为 false，运行时按拆分前的
 *                               固定窗口语义计量；显式配置了 {@code burst-limit}
 *                               的客户端按令牌桶（稳态速率 + 突发余量）计量
 * @param scopeQuotas            按接口范围单独配置的配额，key 为 scope 标识；
 *                               各范围独立计数、互不挤占，缺省的范围共用客户端默认配额
 */
public record ClientCredentials(
        String clientId,
        String secret,
        Set<String> allowedScopes,
        String ownerId,
        long rateLimit,
        long burstLimit,
        boolean defaultBurstConfigured,
        Map<String, QuotaProfile> scopeQuotas
) {
}
