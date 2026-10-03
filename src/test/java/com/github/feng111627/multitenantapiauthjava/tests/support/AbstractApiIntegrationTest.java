package com.github.feng111627.multitenantapiauthjava.tests.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

/**
 * 集成测试基类：启动随机端口的真实 Web 容器，以外部客户端的视角发签名请求。
 *
 * <p>把稳态补充窗口拉长到 6 小时：分范围令牌桶在测试执行期间几乎不补充令牌，
 * 突发/见底/临界判定不依赖真实时间流逝，可稳定复现；令牌的平滑补充与回收
 * 由 ScopeTokenBucketLimiterTest 用可控时钟专门覆盖。
 * 该属性只覆盖单键，不会遮蔽主 application.properties 中的客户端注册表。</p>
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "app.auth.rate-window-seconds=21600")
public abstract class AbstractApiIntegrationTest {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    public static final String SECRET_A = "c2VjcmV0LWEtc2VjcmV0LWEtc2VjcmV0LQ==";
    public static final String SECRET_B = "c2VjcmV0LWItc2VjcmV0LWItc2VjcmV0LQ==";
    public static final String SECRET_LIMITED =
            "c2VjcmV0LWxpbWl0ZWQtc2VjcmV0LWxpbWl0ZWQtc2VjcmV0LQ==";
    public static final String SECRET_NOREAD =
            "c2VjcmV0LW5vcmVhZC1zZWNyZXQtbm9yZWFkLXNlY3JldC0=";
    public static final String SECRET_DEFAULT =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTE=";
    public static final String SECRET_EDGE =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTI=";
    public static final String SECRET_SCOPED_2 =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTM=";
    public static final String SECRET_SCOPED_3 =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTQ=";
    public static final String SECRET_EDGE_2 =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTU=";
    public static final String SECRET_EDGE_3 =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTY=";
    public static final String SECRET_EDGE_4 =
            "c2VjcmV0LXRlc3Qtc2VjcmV0LXRlc3Qtc2VjcmV0LTc=";

    @LocalServerPort
    protected int port;

    @Autowired
    protected ObjectMapper objectMapper;

    protected HttpClient httpClient;

    @BeforeEach
    void initClient() {
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /** 携带完整鉴权头的请求构造器。 */
    protected SignedRequestBuilder signed(String clientId, String secret) {
        return new SignedRequestBuilder(clientId, secret);
    }

    protected String newNonce() {
        return UUID.randomUUID().toString();
    }

    protected String baseUrl(String path) {
        return "http://localhost:" + port + path;
    }

    protected JsonNode parse(HttpResponse<String> response) throws Exception {
        return objectMapper.readTree(response.body());
    }

    /**
     * 带签名的请求构造器，时间戳/nonce/请求体均可在测试中调整，
     * 以便制造"签名错误/时间戳过期/重放"等场景。
     */
    protected class SignedRequestBuilder {
        private final String clientId;
        private final String secret;
        private String method = "POST";
        private String path = "/api/orders/get";
        private long timestamp = System.currentTimeMillis() / 1000;
        private String nonce = newNonce();
        private String requestId = "req-" + UUID.randomUUID();
        private String body = "{}";
        private boolean signHeader = true;
        private String signatureOverride;

        SignedRequestBuilder(String clientId, String secret) {
            this.clientId = clientId;
            this.secret = secret;
        }

        public SignedRequestBuilder method(String method) {
            this.method = method;
            return this;
        }

        public SignedRequestBuilder path(String path) {
            this.path = path;
            return this;
        }

        public SignedRequestBuilder timestamp(long epochSeconds) {
            this.timestamp = epochSeconds;
            return this;
        }

        public SignedRequestBuilder timestampOffsetSeconds(long offset) {
            this.timestamp = System.currentTimeMillis() / 1000 + offset;
            return this;
        }

        public SignedRequestBuilder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public SignedRequestBuilder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public SignedRequestBuilder body(String body) {
            this.body = body;
            return this;
        }

        public SignedRequestBuilder withoutSignatureHeader() {
            this.signHeader = false;
            return this;
        }

        public SignedRequestBuilder tamperSignature() {
            this.signatureOverride = "dGhpcy1pcy1ub3QtYS12YWxpZC1zaWduYXR1cmU=";
            return this;
        }

        public SignedRequestBuilder signBody(String bodyUsedForSigning) {
            // 用篡改前的 body 计算签名，但发送另一个 body
            this.signatureOverride = RequestSigner.signRequest(
                    secret, method, path, timestamp, nonce, bodyUsedForSigning);
            return this;
        }

        public HttpResponse<String> send() throws Exception {
            String signature = signatureOverride != null
                    ? signatureOverride
                    : RequestSigner.signRequest(secret, method, path, timestamp, nonce, body);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl(path)))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("X-Client-Id", clientId)
                    .header("X-Timestamp", Long.toString(timestamp))
                    .header("X-Nonce", nonce)
                    .header("X-Request-Id", requestId);
            if (signHeader) {
                builder.header("X-Signature", signature);
            }
            builder.method(method, HttpRequest.BodyPublishers.ofString(body));

            log.info("test send requestId={} clientId={} path={} nonce={}",
                    requestId, clientId, path, nonce);
            HttpResponse<String> response =
                    httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            log.info("test recv requestId={} status={} body={}",
                    requestId, response.statusCode(), response.body());
            return response;
        }
    }
}
