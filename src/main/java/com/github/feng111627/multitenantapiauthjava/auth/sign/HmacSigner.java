package com.github.feng111627.multitenantapiauthjava.auth.sign;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * HMAC-SHA256 签名工具。
 *
 * <p>签名内容使用 Base64 编码，比较时使用恒定时间比较，避免计时侧信道。</p>
 */
public final class HmacSigner {

    private static final String ALGORITHM = "HmacSHA256";

    private HmacSigner() {
    }

    public static String sign(String secretBase64, String content) {
        try {
            byte[] secret = Base64.getDecoder().decode(secretBase64);
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret, ALGORITHM));
            byte[] raw = mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(raw);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC signing failed", e);
        }
    }

    public static boolean verify(String secretBase64, String content, String signatureBase64) {
        if (signatureBase64 == null || signatureBase64.isEmpty()) {
            return false;
        }
        String expected;
        byte[] provided;
        try {
            expected = sign(secretBase64, content);
            provided = Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] expectedBytes = Base64.getDecoder().decode(expected);
        return MessageDigest.isEqual(expectedBytes, provided);
    }
}
