package com.github.feng111627.multitenantapiauthjava.auth;

/**
 * 当前请求的客户端上下文。
 *
 * 基于 ThreadLocal 做线程隔离：并发请求各自持有自己的客户端身份，
 * 不会出现身份或数据串号；请求结束必须调用 {@link #clear()}。
 */
public final class ClientContext {

    private static final ThreadLocal<ApiClient> CURRENT = new ThreadLocal<>();

    private ClientContext() {
    }

    public static void set(ApiClient client) {
        CURRENT.set(client);
    }

    public static ApiClient get() {
        return CURRENT.get();
    }

    /**
     * 当前请求的客户端身份，未通过鉴权时返回 null。
     */
    public static String currentClientId() {
        ApiClient client = CURRENT.get();
        return client == null ? null : client.clientId();
    }

    /**
     * 当前请求的数据归属租户，未通过鉴权时返回 null。
     */
    public static String currentTenantId() {
        ApiClient client = CURRENT.get();
        return client == null ? null : client.tenantId();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
