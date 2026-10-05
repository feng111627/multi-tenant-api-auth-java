package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 老配置兼容性回归测试。
 *
 * <p>client-legacy：被授予 orders:read 与 orders:export 两个接口范围，只配了
 * 默认 {@code rate-limit=3}，没配突发余量、也没配任何分范围额度。拆分前它整个
 * 客户端一共只有一份默认额度；本类验证修复后：</p>
 * <ul>
 *     <li>多个未单独配置的范围合并计量，跨范围合计每窗口最多放行 3 个；</li>
 *     <li>并发压到边界时跨范围合计恰好放行 3 个（最后一个放行、下一个拒绝）；</li>
 *     <li>伪造签名/未知客户端/缺鉴权头/时间戳过期的请求不占用它的额度；</li>
 *     <li>client-mixed 验证本轮新增的分范围配额不被修复带坏：单独配置的
 *         orders:export 仍独享自己的令牌桶（稳态 5、突发 8），与共享默认额度互不挤占。</li>
 * </ul>
 */
class LegacyQuotaCompatIntegrationTest extends AbstractApiIntegrationTest {

    private HttpResponse<String> callList(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/list").body("{}").send();
    }

    private HttpResponse<String> callExport(String clientId, String secret) throws Exception {
        return signed(clientId, secret).path("/api/orders/export").body("{}").send();
    }

    @Test
    void multipleUnconfiguredScopesShareOneDefaultQuota() throws Exception {
        // 跨范围混合打：read 2 个 + export 1 个用完整份默认额度（合计 3 个）
        assertEquals(200, callList("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(200, callExport("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(200, callList("client-legacy", SECRET_LEGACY).statusCode());

        // 合计已达 3：无论再打哪个范围都必须 429，不能各自再拿一整份
        HttpResponse<String> readRejected = callList("client-legacy", SECRET_LEGACY);
        assertEquals(429, readRejected.statusCode(),
                "跨范围合计已达默认额度，read 必须拒绝，实际：" + readRejected.body());
        HttpResponse<String> exportRejected = callExport("client-legacy", SECRET_LEGACY);
        assertEquals(429, exportRejected.statusCode(),
                "跨范围合计已达默认额度，export 必须拒绝，实际：" + exportRejected.body());

        // 同一时刻重打结果稳定：连续再试仍然都是 429
        assertEquals(429, callList("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(429, callExport("client-legacy", SECRET_LEGACY).statusCode());
        log.info("多范围合并计量用例通过：read+export 合计恰好放行 3 个，其后两个范围都 429");
    }

    @Test
    void sharedQuotaChargedByEitherScopeAddsUpToOneAllowance() throws Exception {
        // 只用 export 一个方向打满 3 个，read 也立即没有额度——证明是同一份额度
        for (int i = 1; i <= 3; i++) {
            assertEquals(200, callExport("client-legacy", SECRET_LEGACY).statusCode(),
                    "export 第 " + i + " 个应放行");
        }
        assertEquals(429, callExport("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(429, callList("client-legacy", SECRET_LEGACY).statusCode(),
                "export 用尽了共享默认额度，read 不能再拿到自己单独的一份");
        log.info("共享额度单向打满用例通过：export 打满 3 个后 read 立即 429");
    }

    @Test
    void concurrentRequestsAcrossScopesShareExactlyOneAllowance() throws Exception {
        // 两个范围各 16 个并发同时打：跨范围合计必须恰好放行 3 个（不是每个范围各 3 个）
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

        assertEquals(3, ok, "跨范围并发压界：合计必须恰好放行 3 个（共享一份默认额度）");
        assertEquals(perScope * 2 - 3, limited);
        log.info("跨范围并发压界用例通过：{} 个并发请求恰好放行 3 个、拒绝 {} 个",
                perScope * 2, limited);
    }

    @Test
    void invalidRequestsDoNotConsumeSharedLegacyQuota() throws Exception {
        for (int i = 0; i < 10; i++) {
            // 伪造签名（知道 clientId 但没有密钥）
            HttpResponse<String> forged = signed("client-legacy", SECRET_LEGACY)
                    .path("/api/orders/export").body("{}").tamperSignature().send();
            assertEquals(401, forged.statusCode());

            // 缺签名头
            HttpResponse<String> missing = signed("client-legacy", SECRET_LEGACY)
                    .path("/api/orders/list").body("{}").withoutSignatureHeader().send();
            assertEquals(401, missing.statusCode());

            // 时间戳过期
            HttpResponse<String> expired = signed("client-legacy", SECRET_LEGACY)
                    .path("/api/orders/export").body("{}")
                    .timestampOffsetSeconds(-10_000).send();
            assertEquals(401, expired.statusCode());

            // 未知客户端
            HttpResponse<String> unknown = signed("client-ghost", SECRET_LEGACY)
                    .path("/api/orders/list").body("{}").send();
            assertEquals(401, unknown.statusCode());
        }

        // 乱打 40 个无效请求之后，client-legacy 的共享默认额度一个都不能少：
        // 跨范围合计仍然恰好是 3 个
        assertEquals(200, callList("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(200, callExport("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(200, callList("client-legacy", SECRET_LEGACY).statusCode());
        assertEquals(429, callExport("client-legacy", SECRET_LEGACY).statusCode(),
                "无效请求不得占用真实额度，第 4 个才应该被拒");
        log.info("无效请求不计入用例通过：40 个无效请求后共享额度仍完整（3 个放行、第 4 个 429）");
    }

    @Test
    void explicitlyScopedQuotaStaysIndependentFromSharedDefault() throws Exception {
        // client-mixed：orders:export 单独配了 5/8 的令牌桶；orders:read 走共享默认（3/窗口）。
        // 先把共享默认额度用 read 打满：
        for (int i = 1; i <= 3; i++) {
            assertEquals(200, callList("client-mixed", SECRET_MIXED).statusCode(),
                    "read 第 " + i + " 个应放行");
        }
        assertEquals(429, callList("client-mixed", SECRET_MIXED).statusCode(),
                "共享默认额度见底，read 第 4 个必须拒绝");

        // 单独配置的 export 不受影响：突发 8 个整波放行、第 9 个见底即拒
        for (int i = 1; i <= 8; i++) {
            assertEquals(200, callExport("client-mixed", SECRET_MIXED).statusCode(),
                    "export 有独立令牌桶，突发第 " + i + " 个应放行");
        }
        assertEquals(429, callExport("client-mixed", SECRET_MIXED).statusCode(),
                "export 突发见底，第 9 个必须拒绝");

        // 反过来 export 见底也不回补共享默认额度：read 仍然 429（各算各的账）
        assertEquals(429, callList("client-mixed", SECRET_MIXED).statusCode());
        log.info("分范围独立不被带坏用例通过：read 共享默认 3 个、export 独立突发 8 个，互不挤占");
    }

    @Test
    void legacyClientDoesNotInterfereWithOtherClients() throws Exception {
        // client-legacy 打满共享额度，不影响 client-limited / client-a 自己的额度
        for (int i = 1; i <= 3; i++) {
            assertEquals(200, callList("client-legacy", SECRET_LEGACY).statusCode());
        }
        assertEquals(429, callList("client-legacy", SECRET_LEGACY).statusCode());

        for (int i = 1; i <= 3; i++) {
            assertEquals(200, callList("client-limited", SECRET_LIMITED).statusCode(),
                    "client-limited 的额度必须独立，第 " + i + " 个应放行");
        }
        assertEquals(429, callList("client-limited", SECRET_LIMITED).statusCode());
        assertEquals(200, callList("client-a", SECRET_A).statusCode());
        log.info("客户端间隔离用例通过：client-legacy 见底不影响 client-limited / client-a");
    }
}
