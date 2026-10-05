package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 老配置兼容性集成测试：被授予多个接口范围、但没有为任何范围单独配置额度的客户端，
 * 必须恢复成"整个客户端共用同一份默认额度"，跨范围合计不放大。
 *
 * <p>涉及客户端：</p>
 * <ul>
 *     <li>{@code client-legacy}：scopes = read + export，只配 rate-limit=4（无突发、
 *     无分范围配额）→ 客户端级共享固定窗口，与拆分前行为一致；</li>
 *     <li>{@code client-burst}：scopes = read + export，rate-limit=2、burst-limit=5
 *     （显式突发、无分范围配额）→ 客户端级共享令牌桶，两个范围共用一份突发容量。</li>
 * </ul>
 */
class LegacySharedQuotaIntegrationTest extends AbstractApiIntegrationTest {

    private HttpResponse<String> callList(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/list").body("{}").send();
    }

    private HttpResponse<String> callExport(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/export").body("{}").send();
    }

    @Test
    @DisplayName("多范围未单独配置：跨范围合计共用一份默认额度（合并计量）")
    void legacyClientSharesOneDefaultQuotaAcrossScopes() throws Exception {
        log.info("scenario=legacy-shared-default client=client-legacy rate=4/window scopes=read+export");
        // 交替打两个范围：合计只能放行 4 个（拆分前整个客户端只有一份默认额度），
        // 而不是 read 4 个 + export 4 个（被放大的行为）
        int ok = 0;
        int limited = 0;
        for (int i = 0; i < 12; i++) {
            HttpResponse<String> response = (i % 2 == 0)
                    ? callList("client-legacy", SECRET_LEGACY)
                    : callExport("client-legacy", SECRET_LEGACY);
            if (response.statusCode() == 200) {
                ok++;
            } else if (response.statusCode() == 429) {
                limited++;
            } else {
                throw new AssertionError("意外状态码：" + response.statusCode());
            }
        }
        assertEquals(4, ok, "跨范围合计放行量必须等于默认额度 4，不能每个范围各拿一份");
        assertEquals(8, limited, "超出共享额度的请求必须 429");
    }

    @Test
    @DisplayName("多范围未单独配置：跨范围并发压界，恰好放满共享额度、下一个即拒")
    void concurrentCrossScopeRequestsShareTheSameBudget() throws Exception {
        log.info("scenario=legacy-shared-default-concurrent client=client-legacy budget=4");
        // 两个范围各 16 个并发同时打：合计恰好 4 个 200，且与调度无关、多轮一致
        for (int run = 0; run < 3; run++) {
            quotaService.reset();
            int perScope = 16;
            ExecutorService pool = Executors.newFixedThreadPool(perScope * 2);
            CountDownLatch ready = new CountDownLatch(perScope * 2);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Integer>> futures = new ArrayList<>();

            for (int i = 0; i < perScope; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    return callList("client-legacy", SECRET_LEGACY).statusCode();
                }));
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    return signed("client-legacy", SECRET_LEGACY)
                            .path("/api/orders/export")
                            .nonce("legacy-export-" + UUID.randomUUID())
                            .body("{}").send().statusCode();
                }));
            }

            ready.await();
            start.countDown();

            int ok = 0;
            int limited = 0;
            for (Future<Integer> f : futures) {
                int status = f.get();
                if (status == 200) {
                    ok++;
                } else if (status == 429) {
                    limited++;
                } else {
                    throw new AssertionError("意外状态码：" + status);
                }
            }
            pool.shutdown();

            assertEquals(4, ok,
                    "第 " + run + " 轮：跨范围并发合计必须恰好放行共享额度 4 个");
            assertEquals(perScope * 2 - 4, limited);
        }
    }

    @Test
    @DisplayName("显式突发的老客户端：多个未单独配置的范围共用同一份默认突发桶")
    void burstConfiguredClientSharesOneDefaultBucketAcrossScopes() throws Exception {
        log.info("scenario=shared-default-burst client=client-burst rate=2 burst=5 scopes=read+export");
        // client-burst 默认突发容量 5：3 个 read + 2 个 export 合计放满 5 个，
        // 第 6 个（无论哪个范围）必须 429——默认额度全客户端只有一份
        for (int i = 1; i <= 3; i++) {
            assertEquals(200, callList("client-burst", SECRET_BURST).statusCode(),
                    "read 第 " + i + " 个应放行（占用共享默认桶）");
        }
        for (int i = 1; i <= 2; i++) {
            assertEquals(200, callExport("client-burst", SECRET_BURST).statusCode(),
                    "export 第 " + i + " 个应放行（与 read 共用同一桶）");
        }
        assertEquals(429, callExport("client-burst", SECRET_BURST).statusCode(),
                "共享突发桶合计已放满 5 个，export 第 6 个必须拒绝");
        assertEquals(429, callList("client-burst", SECRET_BURST).statusCode(),
                "共享突发桶见底后，read 同样必须拒绝（不是各范围各一桶）");
    }

    @Test
    @DisplayName("无效请求不计费：伪造签名/未知客户端/缺头/过期时间戳不占共享默认额度")
    void invalidRequestsDoNotConsumeSharedDefaultQuota() throws Exception {
        log.info("scenario=invalid-requests-not-charged victim=client-legacy");
        for (int i = 0; i < 10; i++) {
            // 伪造签名（知道真实 clientId，没有密钥）
            HttpResponse<String> forged = signed("client-legacy", SECRET_LEGACY)
                    .path("/api/orders/list").body("{}").tamperSignature().send();
            assertEquals(401, forged.statusCode(), "伪造签名必须 401");

            // 缺鉴权头
            HttpResponse<String> missing = signed("client-legacy", SECRET_LEGACY)
                    .path("/api/orders/export").body("{}").withoutSignatureHeader().send();
            assertEquals(401, missing.statusCode(), "缺签名头必须 401");

            // 时间戳过期
            HttpResponse<String> expired = signed("client-legacy", SECRET_LEGACY)
                    .path("/api/orders/list").body("{}")
                    .timestampOffsetSeconds(-10_000).send();
            assertEquals(401, expired.statusCode(), "过期时间戳必须 401");
            assertNotEquals(429, expired.statusCode());

            // 未知客户端
            HttpResponse<String> unknown = signed("client-ghost", SECRET_LEGACY)
                    .path("/api/orders/export").body("{}").send();
            assertEquals(401, unknown.statusCode(), "未知客户端必须 401");
        }

        // 真实共享额度一个都不少：跨范围合计仍恰好 4 个
        int ok = 0;
        for (int i = 0; i < 8; i++) {
            HttpResponse<String> response = (i % 2 == 0)
                    ? callList("client-legacy", SECRET_LEGACY)
                    : callExport("client-legacy", SECRET_LEGACY);
            if (response.statusCode() == 200) {
                ok++;
            }
        }
        assertEquals(4, ok, "40 个无效请求不得占用任何真实额度，共享额度仍完整为 4");

        // 也不算到别的客户端头上：client-a 照常放行
        HttpResponse<String> other = signed("client-a", SECRET_A)
                .path("/api/orders/list").body("{}").send();
        assertEquals(200, other.statusCode(), "无效请求不得影响其它客户端的额度");
    }
}
