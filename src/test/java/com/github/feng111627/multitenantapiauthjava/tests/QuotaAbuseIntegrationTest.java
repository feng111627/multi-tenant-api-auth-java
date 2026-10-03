package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 配额防刷测试：未通过校验的请求不能占用合法客户端的额度，
 * 也不能因为知道 clientId 就把账记到该客户端身上。
 *
 * <p>client-edge 的 orders:ping 桶容量为 3（稳态 3 + 突发 0）。</p>
 */
class QuotaAbuseIntegrationTest extends AbstractApiIntegrationTest {

    private HttpResponse<String> ping(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/ping").body("{}").send();
    }

    @Test
    void forgedRequestsDoNotConsumeRealClientQuota() throws Exception {
        // 1) 攻击者知道 client-edge 的 clientId，用伪造签名乱打一波
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> r = signed("client-edge", SECRET_EDGE)
                    .path("/api/orders/ping")
                    .body("{}")
                    .tamperSignature()
                    .send();
            assertEquals(401, r.statusCode(), "伪造签名必须被拒绝");
        }

        // 2) 缺鉴权头的乱打
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> r = signed("client-edge", SECRET_EDGE)
                    .path("/api/orders/ping")
                    .body("{}")
                    .withoutSignatureHeader()
                    .send();
            assertEquals(401, r.statusCode());
        }

        // 3) 时间戳超窗的乱打
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> r = signed("client-edge", SECRET_EDGE)
                    .path("/api/orders/ping")
                    .body("{}")
                    .timestampOffsetSeconds(-10_000)
                    .send();
            assertEquals(401, r.statusCode());
        }

        // 4) 冒充一个根本不存在的客户端乱打（绝不能记到任何真实客户端头上）
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> r = signed("client-totally-fake", SECRET_EDGE)
                    .path("/api/orders/ping")
                    .body("{}")
                    .send();
            assertEquals(401, r.statusCode());
        }

        // 5) 真正的 client-edge 仍然拥有完整 3 个名额——伪造流量一个都没占掉
        for (int i = 1; i <= 3; i++) {
            HttpResponse<String> r = ping("client-edge", SECRET_EDGE);
            assertEquals(200, r.statusCode(),
                    "被乱打后真实客户端的第 " + i + " 个合法请求仍应放行");
        }
        assertEquals(429, ping("client-edge", SECRET_EDGE).statusCode(),
                "真实客户端自己用完 3 个后才应被限流");
    }

    @Test
    void replayedAndUnauthorizedRequestsDoNotConsumeQuota() throws Exception {
        // 重放请求（第二次起 409）不能占用 orders:ping 的桶
        String nonce = "replay-quota-" + UUID.randomUUID();
        HttpResponse<String> first = signed("client-edge-2", SECRET_EDGE_2)
                .path("/api/orders/ping").body("{}").nonce(nonce).send();
        assertEquals(200, first.statusCode());
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> replay = signed("client-edge-2", SECRET_EDGE_2)
                    .path("/api/orders/ping").body("{}").nonce(nonce).send();
            assertEquals(409, replay.statusCode(), "重放必须 409");
        }

        // client-edge-2 没有 orders:read，越权请求（403）也不能记账
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> denied = signed("client-edge-2", SECRET_EDGE_2)
                    .path("/api/orders/list").body("{}")
                    .nonce("deny-quota-" + UUID.randomUUID())
                    .send();
            assertEquals(403, denied.statusCode());
        }

        // 合法 ping 还应剩 2 个名额（第 1 个已正常使用）
        assertEquals(200, ping("client-edge-2", SECRET_EDGE_2).statusCode());
        assertEquals(200, ping("client-edge-2", SECRET_EDGE_2).statusCode());
        assertEquals(429, ping("client-edge-2", SECRET_EDGE_2).statusCode());
    }
}
