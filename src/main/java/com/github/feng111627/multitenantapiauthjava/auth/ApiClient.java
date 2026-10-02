package com.github.feng111627.multitenantapiauthjava.auth;

import java.util.Set;

/**
 * 外部客户端身份：客户端标识、签名密钥、允许访问的接口范围、数据归属租户。
 */
public record ApiClient(String clientId, String secret, Set<String> allowedPaths, String tenantId) {
}
