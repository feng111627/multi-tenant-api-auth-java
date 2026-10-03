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
 * 分范围配额的集成测试（client-multiscope）：
 * orders:read 稳态/突发均为 3；orders:export 稳态 5、突发 8；默认 100。
 * 各范围独立计数、互不挤占；未通过 scope 校验的请求不计费。
 */
class ScopedQuotaIntegrationTest extends AbstractApiIntegrationTest {

    private HttpResponse<String> callList() throws Exception {
        return signed("client-multiscope", SECRET_MULTISCOPE)
                .path("/api/orders/list").body("{}").send();
    }

    private HttpResponse<String> callExport() throws Exception {
        return signed("client-multiscope", SECRET_MULTISCOPE)
                .path("/api/orders/export").body("{}").send();
    }

    @Test
    void eachScopeHasItsOwnQuota() throws Exception {
        // orders:read 只有 3 的容量：前 3 放行、第 4 个 429
        for (int i = 1; i <= 3; i++) {
            assertEquals(200, callList().statusCode(), "read 第 " + i + " 个应放行");
        }
        HttpResponse<String> readRejected = callList();
        assertEquals(429, readRejected.statusCode());
        assertTrue(parse(readRejected).get("message").asText().contains("orders:read"),
                "429 提示应带具体范围，实际：" + readRejected.body());

        // read 见底不影响 export：export 有自己独立的 8 个突发容量
        for (int i = 1; i <= 8; i++) {
            assertEquals(200, callExport().statusCode(),
                    "read 见底不应挤占 export，export 第 " + i + " 个应放行");
        }
        HttpResponse<String> exportRejected = callExport();
        assertEquals(429, exportRejected.statusCode());
        assertTrue(parse(exportRejected).get("message").asText().contains("orders:export"));
    }

    @Test
    void concurrentRequestsAcrossScopesNeverCrossCharged() throws Exception {
        // 两个范围各自 32 个并发同时打：read 只能成 3 个，export 只能成 8 个，
        // 成功计数互不借用、互不挤占。
        int n = 32;
        ExecutorService pool = Executors.newFixedThreadPool(n * 2);
        CountDownLatch ready = new CountDownLatch(n * 2);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                return callList().statusCode();
            }));
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                return signed("client-multiscope", SECRET_MULTISCOPE)
                        .path("/api/orders/export")
                        .nonce("export-" + UUID.randomUUID())
                        .body("{}").send().statusCode();
            }));
        }

        ready.await();
        start.countDown();

        int readOk = 0;
        int exportOk = 0;
        int readLimited = 0;
        int exportLimited = 0;
        // 偶数下标为 read，奇数为 export
        for (int i = 0; i < futures.size(); i++) {
            int status = futures.get(i).get();
            if (i % 2 == 0) {
                if (status == 200) {
                    readOk++;
                } else if (status == 429) {
                    readLimited++;
                } else {
                    throw new AssertionError("read 意外状态码：" + status);
                }
            } else {
                if (status == 200) {
                    exportOk++;
                } else if (status == 429) {
                    exportLimited++;
                } else {
                    throw new AssertionError("export 意外状态码：" + status);
                }
            }
        }
        pool.shutdown();

        assertEquals(3, readOk, "read 范围并发成功数必须严格等于其突发容量 3");
        assertEquals(8, exportOk, "export 范围并发成功数必须严格等于其突发容量 8");
        assertEquals(n - 3, readLimited);
        assertEquals(n - 8, exportLimited);
    }

    @Test
    void scopeDeniedRequestsDoNotConsumeQuota() throws Exception {
        // client-noread 没有任何 scope，所有请求都 403；
        // 这些被拒请求绝不能消耗 client-a 同名范围的额度（不同客户端也不串）。
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> denied = signed("client-noread", SECRET_NOREAD)
                    .path("/api/orders/list").body("{}").send();
            assertEquals(403, denied.statusCode(), "scope 不足必须 403");
        }

        // client-a 的 orders:read 不受影响，照常放行
        HttpResponse<String> ok = signed("client-a", SECRET_A)
                .path("/api/orders/list").body("{}").send();
        assertEquals(200, ok.statusCode());
    }
}
