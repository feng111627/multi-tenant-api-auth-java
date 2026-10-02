package com.github.feng111627.multitenantapiauthjava.auth.sign;

import com.github.feng111627.multitenantapiauthjava.auth.config.AuthProperties;
import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * 验签服务。
 *
 * <p>判定顺序（每一步失败给出可区分的错误码）：</p>
 * <ol>
 *     <li>时间戳必须落在 {@code now ± timestampSkewSeconds} 窗口内（容忍客户端/服务端时钟偏差）；</li>
 *     <li>签名必须与服务端按同一规范串重新计算的 HMAC-SHA256 一致；</li>
 *     <li>同一 client 下的 nonce 在 TTL 窗口内只能出现一次（重放检测）。</li>
 * </ol>
 *
 * <p>规范串：{@code METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(BODY)}。</p>
 */
@Service
public class SignatureService {

    /** 请求头字段名。 */
    public static final String HEADER_CLIENT_ID = "X-Client-Id";
    public static final String HEADER_TIMESTAMP = "X-Timestamp";
    public static final String HEADER_NONCE = "X-Nonce";
    public static final String HEADER_SIGNATURE = "X-Signature";
    public static final String HEADER_REQUEST_ID = "X-Request-Id";

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    private final AuthProperties properties;
    private final ReplayCache replayCache;

    public SignatureService(AuthProperties properties, ReplayCache replayCache) {
        this.properties = properties;
        this.replayCache = replayCache;
    }

    /**
     * 校验请求签名；任何一项不通过都抛出带明确错误码的 {@link ApiException}。
     */
    public void verify(HttpServletRequest request, ClientCredentials client) {
        String timestampHeader = request.getHeader(HEADER_TIMESTAMP);
        String nonce = request.getHeader(HEADER_NONCE);
        String signature = request.getHeader(HEADER_SIGNATURE);
        String requestId = resolveRequestId(request, nonce);

        long timestamp;
        try {
            timestamp = Long.parseLong(timestampHeader == null ? "" : timestampHeader.trim());
        } catch (NumberFormatException e) {
            reject(client.clientId(), requestId, nonce, ErrorCode.TIMESTAMP_EXPIRED,
                    "missing or malformed timestamp header");
            return;
        }

        long skewMillis = properties.getTimestampSkewSeconds() * 1000L;
        long delta = Math.abs(System.currentTimeMillis() - timestamp * 1000L);
        if (delta > skewMillis) {
            reject(client.clientId(), requestId, nonce, ErrorCode.TIMESTAMP_EXPIRED,
                    "timestamp drift " + delta + "ms exceeds skew window " + skewMillis + "ms");
        }

        String body = readBody(request);
        String canonical = canonicalString(request.getMethod(), request.getRequestURI(),
                timestamp, nonce, body);
        if (!HmacSigner.verify(client.secret(), canonical, signature)) {
            reject(client.clientId(), requestId, nonce, ErrorCode.INVALID_SIGNATURE,
                    "signature does not match canonical request");
        }

        long ttlMillis = properties.getNonceTtlSeconds() * 1000L;
        boolean firstSeen = replayCache.registerIfAbsent(client.clientId(), nonce, ttlMillis);
        if (!firstSeen) {
            reject(client.clientId(), requestId, nonce, ErrorCode.REPLAY_DETECTED,
                    "nonce already used within replay window");
        }

        log.info("auth accepted clientId={} requestId={} nonce={} reason=signature_ok",
                client.clientId(), requestId, nonce);
    }

    /**
     * 构建签名规范串（客户端必须按相同规则构造）。
     */
    public static String canonicalString(String method, String path, long timestamp,
                                         String nonce, String body) {
        String bodyHash = sha256Hex(body == null ? "" : body);
        return String.join("\n",
                method.toUpperCase(),
                path,
                Long.toString(timestamp),
                nonce == null ? "" : nonce,
                bodyHash);
    }

    private static String resolveRequestId(HttpServletRequest request, String fallback) {
        String requestId = request.getHeader(HEADER_REQUEST_ID);
        if (requestId != null && !requestId.isBlank()) {
            return requestId;
        }
        return fallback == null ? "-" : fallback;
    }

    private static String readBody(HttpServletRequest request) {
        try {
            return new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ApiException(ErrorCode.INTERNAL_ERROR, "failed to read request body");
        }
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static void reject(String clientId, String requestId, String nonce,
                               ErrorCode code, String reason) {
        log.warn("auth rejected clientId={} requestId={} nonce={} code={} reason={}",
                clientId, requestId, nonce, code.code(), reason);
        throw new ApiException(code, reason);
    }
}
