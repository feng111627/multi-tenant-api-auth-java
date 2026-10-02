package com.github.feng111627.multitenantapiauthjava.auth.model;

/**
 * 鉴权通过后绑定到当前请求的客户端身份。
 * 仅通过 ThreadLocal 持有，保证并发请求之间互不串号。
 */
public final class ClientContext {

    private static final ThreadLocal<ClientCredentials> HOLDER = new ThreadLocal<>();

    private ClientContext() {
    }

    public static void set(ClientCredentials credentials) {
        HOLDER.set(credentials);
    }

    public static ClientCredentials get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }
}
