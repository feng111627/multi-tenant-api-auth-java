package com.github.feng111627.multitenantapiauthjava.tests.support;

import com.github.feng111627.multitenantapiauthjava.auth.sign.HmacSigner;
import com.github.feng111627.multitenantapiauthjava.auth.sign.SignatureService;

/**
 * 测试用请求签名工具，规范串构造与服务端 {@link SignatureService} 保持一致。
 */
public final class RequestSigner {

    private RequestSigner() {
    }

    public static String canonicalRequest(String method, String path, long timestamp,
                                          String nonce, String body) {
        return SignatureService.canonicalString(method, path, timestamp, nonce,
                body == null ? "" : body);
    }

    public static String sign(String secretBase64, String content) {
        return HmacSigner.sign(secretBase64, content);
    }

    /**
     * 便捷方法：直接生成签名头值。
     */
    public static String signRequest(String secretBase64, String method, String path,
                                     long timestamp, String nonce, String body) {
        return sign(secretBase64, canonicalRequest(method, path, timestamp, nonce, body));
    }
}
