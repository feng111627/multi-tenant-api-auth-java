package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 验签相关场景：成功、缺头、未知客户端、签名错误、时间戳超窗、时钟偏差容忍、重放。
 */
class SignatureVerificationTest extends AbstractApiIntegrationTest {

    private static final String GET_BODY = "{\"orderId\":\"ORD-1001\"}";

    @Test
    void validSignatureWithinSkewIsAccepted() throws Exception {
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .send();

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("ORD-1001"));
    }

    @Test
    void fewSecondsClockSkewIsTolerated() throws Exception {
        // 客户端时钟比服务端快 3 秒，必须在容忍范围内，不能误伤
        HttpResponse<String> fast = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .timestampOffsetSeconds(3)
                .send();
        assertEquals(200, fast.statusCode(), "客户端快 3 秒应被容忍");

        // 客户端时钟比服务端慢 3 秒
        HttpResponse<String> slow = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .timestampOffsetSeconds(-3)
                .send();
        assertEquals(200, slow.statusCode(), "客户端慢 3 秒应被容忍");
    }

    @Test
    void missingSignatureHeaderIsRejected() throws Exception {
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .withoutSignatureHeader()
                .send();

        assertEquals(401, response.statusCode());
        assertEquals("AUTH_MISSING_CREDENTIALS", parse(response).get("code").asText());
    }

    @Test
    void unknownClientIsRejected() throws Exception {
        HttpResponse<String> response = signed("client-does-not-exist", SECRET_A)
                .body(GET_BODY)
                .send();

        assertEquals(401, response.statusCode());
        assertEquals("AUTH_UNKNOWN_CLIENT", parse(response).get("code").asText());
    }

    @Test
    void wrongSignatureIsRejected() throws Exception {
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .tamperSignature()
                .send();

        assertEquals(401, response.statusCode());
        assertEquals("AUTH_INVALID_SIGNATURE", parse(response).get("code").asText());
    }

    @Test
    void signatureOverDifferentBodyIsRejected() throws Exception {
        // 签名是针对旧 body 算的，发送时换成新 body：body 摘要不匹配
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .signBody(GET_BODY)
                .body("{\"orderId\":\"ORD-2001\"}")
                .send();

        assertEquals(401, response.statusCode());
        assertEquals("AUTH_INVALID_SIGNATURE", parse(response).get("code").asText());
    }

    @Test
    void timestampOutsideWindowIsRejected() throws Exception {
        HttpResponse<String> response = signed("client-a", SECRET_A)
                .body(GET_BODY)
                // 默认窗口 300 秒，超出 10 分钟
                .timestampOffsetSeconds(400)
                .send();

        assertEquals(401, response.statusCode());
        assertEquals("AUTH_TIMESTAMP_EXPIRED", parse(response).get("code").asText());
    }

    @Test
    void sameNonceSubmittedTwiceIsRejectedAsReplay() throws Exception {
        String fixedNonce = "fixed-nonce-replay-" + System.nanoTime();

        HttpResponse<String> first = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .nonce(fixedNonce)
                .send();
        assertEquals(200, first.statusCode(), "首次提交应通过");

        // 完全相同的请求标识（clientId + nonce）再次提交：必须判重放，
        // 即使重新签名也不行
        HttpResponse<String> second = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .nonce(fixedNonce)
                .send();
        assertEquals(409, second.statusCode());
        assertEquals("AUTH_REPLAY_DETECTED", parse(second).get("code").asText());
    }

    @Test
    void sameNonceFromDifferentClientsIsNotReplay() throws Exception {
        // nonce 按客户端维度隔离：A 用过的 nonce，B 用不算重放
        String sharedNonce = "shared-nonce-" + System.nanoTime();

        HttpResponse<String> fromA = signed("client-a", SECRET_A)
                .body(GET_BODY)
                .nonce(sharedNonce)
                .send();
        assertEquals(200, fromA.statusCode());

        HttpResponse<String> fromB = signed("client-b", SECRET_B)
                .body("{\"orderId\":\"ORD-2001\"}")
                .nonce(sharedNonce)
                .send();
        assertEquals(200, fromB.statusCode());
    }
}
