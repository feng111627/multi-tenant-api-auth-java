package com.github.feng111627.multitenantapiauthjava.auth.model;

import java.util.Set;

/**
 * 一个外部客户端的身份与访问范围配置。
 *
 * @param clientId       客户端标识
 * @param secret         HMAC 密钥（Base64 编码）
 * @param allowedScopes  允许访问的接口范围（scope 标识集合）
 * @param ownerId        数据归属标识（租户/数据所有者）
 * @param rateLimit      每个统计窗口允许的最大请求数
 */
public record ClientCredentials(
        String clientId,
        String secret,
        Set<String> allowedScopes,
        String ownerId,
        long rateLimit
) {
}
