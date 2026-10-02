package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.auth.SignatureUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 鉴权与访问控制集成测试。
 *
 * 测试客户端：
 *  - client-a / tenant-a / 允许 /api/orders 及子路径
 *  - client-b / tenant-b / 仅允许 /api/orders（不含子路径）
 *  - client-rl / tenant-rl / 限流容量固定为 3、不补充，用于临界值测试
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "auth.timestamp-tolerance-millis=300000",
        "auth.nonce-ttl-millis=300000",
        "ratelimit.capacity=100",
        "ratelimit.refill-per-second=0",
        "ratelimit.capacity-overrides=client-rl:3",
        "auth.clients[0].client-id=client-a",
        "auth.clients[0].secret=secret-for-client-a",
        "auth.clients[0].tenant-id=tenant-a",
        "auth.clients[0].allowed-paths=/api/orders,/api/orders/**",
        "auth.clients[1].client-id=client-b",
        "auth.clients[1].secret=secret-for-client-b",
        "auth.clients[1].tenant-id=tenant-b",
        "auth.clients[1].allowed-paths=/api/orders",
        "auth.clients[2].client-id=client-rl",
        "auth.clients[2].secret=secret-for-client-rl",
        "auth.clients[2].tenant-id=tenant-rl",
        "auth.clients[2].allowed-paths=/api/orders"
})
class ApiAuthIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ApiAuthIntegrationTest.class);

    @Autowired
    private TestRestTemplate rest;

    // ---------- 签名请求构造 ----------

    private HttpEntity<String> signedRequest(String clientId, String secret, String method,
                                             String path, String body, long timestamp, String nonce) {
        String canonical = SignatureUtils.buildCanonicalString(method, path,
                String.valueOf(timestamp), nonce, body);
        String signature = SignatureUtils.sign(secret, canonical);
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Client-Id", clientId);
        headers.set("X-Timestamp", String.valueOf(timestamp));
        headers.set("X-Nonce", nonce);
        headers.set("X-Signature", signature);
        headers.set(HttpHeaders.CONTENT_TYPE, "application/json");
        return new HttpEntity<>(body, headers);
    }

    private String newNonce() {
        return UUID.randomUUID().toString();
    }

    private ResponseEntity<String> get(String clientId, String secret, String path) {
        String nonce = newNonce();
        ResponseEntity<String> resp = rest.exchange(path, HttpMethod.GET,
                signedRequest(clientId, secret, "GET", path, "", System.currentTimeMillis(), nonce),
                String.class);
        log.info("requestId={}:{} decision={} status={}", clientId, nonce, "GET " + path, resp.getStatusCode());
        return resp;
    }

    // ---------- 正常访问与数据隔离 ----------

    @Test
    void validSignaturePassesAndDataIsTenantScoped() {
        ResponseEntity<String> ra = get("client-a", "secret-for-client-a", "/api/orders");
        assertThat(ra.getStatusCode().value()).isEqualTo(200);
        assertThat(ra.getBody()).contains("keyboard").doesNotContain("monitor");

        ResponseEntity<String> rb = get("client-b", "secret-for-client-b", "/api/orders");
        assertThat(rb.getStatusCode().value()).isEqualTo(200);
        assertThat(rb.getBody()).contains("monitor").doesNotContain("keyboard");
        log.info("tenant isolation verified: client-a and client-b see disjoint order sets");
    }

    @Test
    void smallClockSkewIsTolerated() {
        long skewed = System.currentTimeMillis() - 3000; // 3 秒偏差
        String nonce = newNonce();
        ResponseEntity<String> resp = rest.exchange("/api/orders", HttpMethod.GET,
                signedRequest("client-a", "secret-for-client-a", "GET", "/api/orders", "", skewed, nonce),
                String.class);
        log.info("requestId=client-a:{} decision=timestamp skew 3000ms within tolerance status={}",
                nonce, resp.getStatusCode());
        assertThat(resp.getStatusCode().value()).isEqualTo(200);
    }

    // ---------- 验签失败 ----------

    @Test
    void invalidSignatureIsRejected() {
        ResponseEntity<String> resp = get("client-a", "wrong-secret", "/api/orders");
        assertThat(resp.getStatusCode().value()).isEqualTo(401);
        assertThat(resp.getBody()).contains("SIGNATURE_INVALID");
    }

    @Test
    void unknownClientIsRejected() {
        ResponseEntity<String> resp = get("no-such-client", "whatever", "/api/orders");
        assertThat(resp.getStatusCode().value()).isEqualTo(401);
        assertThat(resp.getBody()).contains("CLIENT_UNKNOWN");
    }

    // ---------- 时间戳 ----------

    @Test
    void staleTimestampIsRejected() {
        long stale = System.currentTimeMillis() - 3600_000; // 1 小时前
        String nonce = newNonce();
        ResponseEntity<String> resp = rest.exchange("/api/orders", HttpMethod.GET,
                signedRequest("client-a", "secret-for-client-a", "GET", "/api/orders", "", stale, nonce),
                String.class);
        log.info("requestId=client-a:{} decision=timestamp skew 3600000ms exceeds tolerance status={}",
                nonce, resp.getStatusCode());
        assertThat(resp.getStatusCode().value()).isEqualTo(401);
        assertThat(resp.getBody()).contains("TIMESTAMP_EXPIRED");
    }

    // ---------- 重放 ----------

    @Test
    void replayedNonceIsRejected() {
        String nonce = newNonce();
        long now = System.currentTimeMillis();
        HttpEntity<String> req = signedRequest("client-a", "secret-for-client-a",
                "GET", "/api/orders", "", now, nonce);

        ResponseEntity<String> first = rest.exchange("/api/orders", HttpMethod.GET, req, String.class);
        log.info("requestId=client-a:{} decision=first submission status={}", nonce, first.getStatusCode());
        assertThat(first.getStatusCode().value()).isEqualTo(200);

        ResponseEntity<String> replay = rest.exchange("/api/orders", HttpMethod.GET, req, String.class);
        log.info("requestId=client-a:{} decision=replayed nonce status={}", nonce, replay.getStatusCode());
        assertThat(replay.getStatusCode().value()).isEqualTo(401);
        assertThat(replay.getBody()).contains("NONCE_REPLAYED");
    }

    // ---------- 越权 ----------

    @Test
    void pathOutsideScopeIsRejected() {
        // client-b 只允许 /api/orders，访问子路径应被 SCOPE_FORBIDDEN 拒绝
        ResponseEntity<String> resp = get("client-b", "secret-for-client-b", "/api/orders/b-1");
        assertThat(resp.getStatusCode().value()).isEqualTo(403);
        assertThat(resp.getBody()).contains("SCOPE_FORBIDDEN");
    }

    @Test
    void crossTenantDataIsNotLeaked() {
        // client-a 访问 tenant-b 的订单 b-1：路径在范围内，但数据不属于 tenant-a
        ResponseEntity<String> resp = get("client-a", "secret-for-client-a", "/api/orders/b-1");
        assertThat(resp.getStatusCode().value()).isEqualTo(403);
        assertThat(resp.getBody()).contains("TENANT_FORBIDDEN");
        assertThat(resp.getBody()).doesNotContain("monitor");
    }

    // ---------- 限流临界值 ----------

    @Test
    void rateLimitBoundaryIsEnforced() {
        // client-rl 容量为 3 且不补充：前 3 个请求通过，第 4 个被限流
        for (int i = 1; i <= 3; i++) {
            ResponseEntity<String> resp = get("client-rl", "secret-for-client-rl", "/api/orders");
            assertThat(resp.getStatusCode().value()).as("request %d within capacity", i).isEqualTo(200);
        }
        ResponseEntity<String> rejected = get("client-rl", "secret-for-client-rl", "/api/orders");
        assertThat(rejected.getStatusCode().value()).isEqualTo(429);
        assertThat(rejected.getBody()).contains("RATE_LIMITED");
        log.info("rate limit boundary verified: 3 passed, 4th rejected with RATE_LIMITED");
    }

    // ---------- 并发 ----------

    @Test
    void concurrentRequestsDoNotMixIdentities() throws Exception {
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<String>> tasks = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                boolean useA = i % 2 == 0;
                String clientId = useA ? "client-a" : "client-b";
                String secret = useA ? "secret-for-client-a" : "secret-for-client-b";
                String expected = useA ? "keyboard" : "monitor";
                String forbidden = useA ? "monitor" : "keyboard";
                tasks.add(() -> {
                    ResponseEntity<String> resp = get(clientId, secret, "/api/orders");
                    assertThat(resp.getStatusCode().value()).isEqualTo(200);
                    assertThat(resp.getBody()).contains(expected).doesNotContain(forbidden);
                    return clientId;
                });
            }
            List<Future<String>> results = pool.invokeAll(tasks);
            for (Future<String> f : results) {
                f.get(); // 任一断言失败会在此抛出
            }
            log.info("concurrency verified: {} parallel requests, no identity/tenant mix-up", threads);
        } finally {
            pool.shutdownNow();
        }
    }

    // ---------- 参数错误统一返回 ----------

    @Test
    void badRequestReturnsStableErrorBody() {
        String nonce = newNonce();
        String body = "{\"item\":\"desk\"}"; // 缺少 amount
        ResponseEntity<String> resp = rest.exchange("/api/orders", HttpMethod.POST,
                signedRequest("client-a", "secret-for-client-a", "POST", "/api/orders", body,
                        System.currentTimeMillis(), nonce),
                String.class);
        log.info("requestId=client-a:{} decision=missing amount status={}", nonce, resp.getStatusCode());
        assertThat(resp.getStatusCode().value()).isEqualTo(400);
        assertThat(resp.getBody()).contains("BAD_REQUEST");
    }
}
