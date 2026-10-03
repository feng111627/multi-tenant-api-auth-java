package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 配额防刷集成测试：外部人员知道一个真实 clientId 后伪造请求乱打，
 * 这些未通过校验的请求不能占用该客户端真正可用的额度，也不会算到别的客户端身上。
 */
class QuotaAbuseIntegrationTest extends AbstractApiIntegrationTest {

    @Test
    void requestsWithForgedSignatureDoNotConsumeVictimsQuota() throws Exception {
        // 攻击者知道 client-limited 的 clientId，但没有密钥，乱发一批签名错误的请求
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> forged = signed("client-limited", SECRET_LIMITED)
                    .path("/api/orders/list")
                    .body("{}")
                    .tamperSignature()
                    .send();
            assertEquals(401, forged.statusCode(), "伪造签名必须被验签拒绝");
        }

        // 真正持有密钥的 client-limited：它的 3 个额度一个都不能少
        for (int i = 1; i <= 3; i++) {
            HttpResponse<String> legit = signed("client-limited", SECRET_LIMITED)
                    .path("/api/orders/list").body("{}").send();
            assertEquals(200, legit.statusCode(),
                    "伪造请求不应消耗真实额度，第 " + i + " 个合法请求应放行");
        }
        assertEquals(429, signed("client-limited", SECRET_LIMITED)
                .path("/api/orders/list").body("{}").send().statusCode());
    }

    @Test
    void requestsForUnknownClientNeverCreateOrChargeAnyBucket() throws Exception {
        // 用一个不存在的 clientId 乱打：一律 401，不影响任何真实客户端
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> unknown = signed("client-does-not-exist", SECRET_A)
                    .path("/api/orders/list").body("{}").send();
            assertEquals(401, unknown.statusCode());
        }

        // client-limited 与 client-a 都照常拥有各自完整额度
        assertEquals(200, signed("client-limited", SECRET_LIMITED)
                .path("/api/orders/list").body("{}").send().statusCode());
        HttpResponse<String> a = signed("client-a", SECRET_A)
                .path("/api/orders/list").body("{}").send();
        assertEquals(200, a.statusCode());
    }

    @Test
    void missingHeadersAndBadTimestampDoNotConsumeQuota() throws Exception {
        for (int i = 0; i < 10; i++) {
            // 缺签名头：401，且不占额度
            HttpResponse<String> missing = signed("client-limited", SECRET_LIMITED)
                    .path("/api/orders/list").body("{}").withoutSignatureHeader().send();
            assertEquals(401, missing.statusCode());

            // 时间戳严重过期：401，且不占额度
            HttpResponse<String> expired = signed("client-limited", SECRET_LIMITED)
                    .path("/api/orders/list").body("{}")
                    .timestampOffsetSeconds(-10_000).send();
            assertEquals(401, expired.statusCode());
            assertNotEquals(429, expired.statusCode());
        }

        // 额度仍完整
        for (int i = 1; i <= 3; i++) {
            assertEquals(200, signed("client-limited", SECRET_LIMITED)
                    .path("/api/orders/list").body("{}").send().statusCode());
        }
    }
}
