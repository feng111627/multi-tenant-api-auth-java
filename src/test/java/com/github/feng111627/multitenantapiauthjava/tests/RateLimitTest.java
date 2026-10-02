package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 按客户端维度的限流临界值测试。client-limited 每窗口限额 3。
 */
class RateLimitTest extends AbstractApiIntegrationTest {

    @Test
    void requestsAtAndOverLimitAreHandledStably() throws Exception {
        // 第 1~3 个请求（恰好达到限额）必须全部放行
        for (int i = 1; i <= 3; i++) {
            HttpResponse<String> response = signed("client-limited", SECRET_LIMITED)
                    .path("/api/orders/list")
                    .body("{}")
                    .send();
            assertEquals(200, response.statusCode(),
                    "第 " + i + " 个请求处于限额内，应放行");
        }

        // 第 4 个请求越过临界值，必须被拒绝并给出可识别错误码与提示
        HttpResponse<String> rejected = signed("client-limited", SECRET_LIMITED)
                .path("/api/orders/list")
                .body("{}")
                .send();
        assertEquals(429, rejected.statusCode());
        JsonNode body = parse(rejected);
        assertEquals("RATE_LIMITED", body.get("code").asText());
        assertTrue(body.get("message").asText().contains("rate limit"),
                "限流提示应可识别，实际：" + body.get("message").asText());
        assertTrue(rejected.headers().firstValue("Content-Type").orElse("")
                .contains("application/json"));
    }

    @Test
    void rateLimitIsIsolatedPerClient() throws Exception {
        // client-limited 被限流不影响 client-a：限流维度必须独立
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body("{\"orderId\":\"ORD-1001\"}")
                .send();
        assertEquals(200, response.statusCode());
    }
}
