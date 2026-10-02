package com.github.feng111627.multitenantapiauthjava.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * 签名工具：构造待签名串并计算/校验 HMAC-SHA256 签名。
 *
 * 待签名串格式（按行拼接）：
 *   METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(BODY)
 */
public final class SignatureUtils {

    private SignatureUtils() {
    }

    public static String buildCanonicalString(String method, String path, String timestamp, String nonce, String body) {
        String bodyHash = sha256Hex(body == null ? "" : body);
        return String.join("\n",
                method == null ? "" : method.toUpperCase(),
                path == null ? "" : path,
                timestamp == null ? "" : timestamp,
                nonce == null ? "" : nonce,
                bodyHash);
    }

    public static String sign(String secret, String canonicalString) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(canonicalString.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("failed to compute HMAC-SHA256", e);
        }
    }

    /**
     * 常量时间比较，避免时序侧信道。
     */
    public static boolean signatureEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("failed to compute SHA-256", e);
        }
    }
}
