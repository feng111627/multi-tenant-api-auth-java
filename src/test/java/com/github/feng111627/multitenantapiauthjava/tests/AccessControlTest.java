package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 访问控制场景：接口范围(scope)越权、数据归属(owner)越权、列表不泄露他人数据。
 */
class AccessControlTest extends AbstractApiIntegrationTest {

    @Test
    void clientWithoutScopeIsDenied() throws Exception {
        // client-noread 身份有效、签名正确，但没有 orders:read 范围
        HttpResponse<String> response = signed("client-noread", SECRET_NOREAD)
                .body("{\"orderId\":\"ORD-1001\"}")
                .send();

        assertEquals(403, response.statusCode());
        assertEquals("ACCESS_DENIED", parse(response).get("code").asText());
    }

    @Test
    void clientCanReadOwnOrder() throws Exception {
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body("{\"orderId\":\"ORD-1001\"}")
                .send();

        assertEquals(200, response.statusCode());
        JsonNode body = parse(response);
        assertEquals("ORD-1001", body.get("orderId").asText());
        assertEquals("tenant-a", body.get("ownerId").asText());
    }

    @Test
    void clientCannotReadAnotherTenantsOrderById() throws Exception {
        // client-a 知道 tenant-b 的订单号，直接越权查询：
        // 必须拒绝且不能泄露数据存在性以外的任何信息
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body("{\"orderId\":\"ORD-2001\"}")
                .send();

        assertEquals(400, response.statusCode());
        assertEquals("PARAM_INVALID", parse(response).get("code").asText());
        assertFalse(response.body().contains("tenant-b"),
                "越权响应中不能出现数据归属信息");
        assertFalse(response.body().contains("B 公司"),
                "越权响应中不能泄露他人数据内容");
    }

    @Test
    void listOnlyReturnsOwnersOwnData() throws Exception {
        HttpResponse<String> responseA = signed("client-a", SECRET_A)
                .path("/api/orders/list")
                .body("{}")
                .send();
        assertEquals(200, responseA.statusCode());
        String bodyA = responseA.body();
        assertTrue(bodyA.contains("ORD-1001"));
        assertTrue(bodyA.contains("ORD-1002"));
        assertFalse(bodyA.contains("ORD-2001"), "A 的列表不能包含 B 的订单");
        assertFalse(bodyA.contains("ORD-2002"), "A 的列表不能包含 B 的订单");
        assertFalse(bodyA.contains("tenant-b"), "A 的列表不能泄露 B 的归属标识");

        HttpResponse<String> responseB = signed("client-b", SECRET_B)
                .path("/api/orders/list")
                .body("{}")
                .send();
        assertEquals(200, responseB.statusCode());
        String bodyB = responseB.body();
        assertTrue(bodyB.contains("ORD-2001"));
        assertTrue(bodyB.contains("ORD-2002"));
        assertFalse(bodyB.contains("ORD-1001"), "B 的列表不能包含 A 的订单");
    }

    @Test
    void invalidParameterReturnsStableErrorShape() throws Exception {
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body("{\"orderId\":\"\"}")
                .send();

        assertEquals(400, response.statusCode());
        JsonNode body = parse(response);
        assertEquals("PARAM_INVALID", body.get("code").asText());
        assertTrue(body.has("requestId"));
        assertTrue(body.has("timestamp"));
        assertTrue(body.has("message"));
    }
}
