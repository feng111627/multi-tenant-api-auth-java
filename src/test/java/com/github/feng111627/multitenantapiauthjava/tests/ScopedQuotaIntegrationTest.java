package com.github.feng111627.multitenantapiauthjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 分范围配额集成测试（真实 Web 容器 + 签名请求）。
 *
 * <p>client-scoped：orders:read 稳态 2 + 突发 2；orders:ping 稳态 5 无突发；
 * client-default：orders:ping 未单独配置，沿用默认固定窗口 2。</p>
 */
class ScopedQuotaIntegrationTest extends AbstractApiIntegrationTest {

    private HttpResponse<String> ping(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/ping").body("{}").send();
    }

    private HttpResponse<String> list(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/list").body("{}").send();
    }

    @Test
    void quotasAreCountedIndependentlyPerScope() throws Exception {
        // orders:read 桶容量 4（稳态 2 + 突发 2），连发 4 个全部放行
        for (int i = 1; i <= 4; i++) {
            HttpResponse<String> r = list("client-scoped-2", SECRET_SCOPED_2);
            assertEquals(200, r.statusCode(), "orders:read 第 " + i + " 个应在突发容量内");
        }
        // orders:read 见底：第 5 个 429
        HttpResponse<String> readRejected = list("client-scoped-2", SECRET_SCOPED_2);
        assertEquals(429, readRejected.statusCode());
        JsonNode rejectedBody = parse(readRejected);
        assertEquals("RATE_LIMITED", rejectedBody.get("code").asText());
        assertTrue(rejectedBody.get("message").asText().contains("orders:read"),
                "拒绝信息应能看出归属范围，实际：" + rejectedBody.get("message").asText());

        // orders:ping 是另一本账：orders:read 被打空对它毫无影响，5 个全部放行
        for (int i = 1; i <= 5; i++) {
            HttpResponse<String> r = ping("client-scoped-2", SECRET_SCOPED_2);
            assertEquals(200, r.statusCode(),
                    "orders:ping 第 " + i + " 个不应受 orders:read 配额影响");
        }
        HttpResponse<String> pingRejected = ping("client-scoped-2", SECRET_SCOPED_2);
        assertEquals(429, pingRejected.statusCode(), "orders:ping 自身的第 6 个应被拒");
        assertTrue(parse(pingRejected).get("message").asText().contains("orders:ping"));
    }

    @Test
    void unconfiguredScopeFallsBackToClientDefaultLimit() throws Exception {
        // client-default 的 orders:ping 没有单独配额，沿用客户端默认 rate-limit=2（旧固定窗口行为）
        assertEquals(200, ping("client-default", SECRET_DEFAULT).statusCode());
        assertEquals(200, ping("client-default", SECRET_DEFAULT).statusCode());
        HttpResponse<String> rejected = ping("client-default", SECRET_DEFAULT);
        assertEquals(429, rejected.statusCode());
        JsonNode body = parse(rejected);
        assertEquals("RATE_LIMITED", body.get("code").asText());
        assertTrue(body.get("message").asText().contains("bucket=default"),
                "未配置独立配额的范围必须走默认桶，实际：" + body.get("message").asText());
    }

    @Test
    void burstWaveIsAcceptedWholeThenDrained() throws Exception {        // 稳态 2 + 突发 2：短时间一波 4 个整波放行，第 5 个见底拒绝
        for (int i = 1; i <= 4; i++) {
            assertEquals(200, list("client-scoped-3", SECRET_SCOPED_3).statusCode(),
                    "突发波第 " + i + " 个应整波放行");
        }
        assertEquals(429, list("client-scoped-3", SECRET_SCOPED_3).statusCode(),
                "突发见底后必须立刻拒绝，不能多放");
    }
}
