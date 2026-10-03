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

/**
 * 分范围配额并发测试：
 * 1) 突发见底时并发压到边界——恰好容量个放行，其余稳定拒绝，多轮重跑结果一致；
 * 2) 同一客户端两个不同 scope 的并发请求各记各的账，计数互不串。
 */
class QuotaConcurrencyTest extends AbstractApiIntegrationTest {

    private static final int ATTEMPTS = 32;

    /** 同一 scope 容量 3，32 个请求同时冲：必须恰好 3 个 200、其余 429。 */
    @Test
    void exactlyCapacityRequestsPassUnderConcurrentBurst() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(ATTEMPTS);
        CountDownLatch ready = new CountDownLatch(ATTEMPTS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();

        for (int i = 0; i < ATTEMPTS; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                HttpResponse<String> r = signed("client-edge-4", SECRET_EDGE_4)
                        .path("/api/orders/ping")
                        .body("{}")
                        .nonce("edge-burst-" + UUID.randomUUID())
                        .send();
                return r.statusCode();
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
                throw new AssertionError("意外的状态码：" + status);
            }
        }
        pool.shutdown();

        assertEquals(3, ok, "并发达界：恰好容量 3 个请求放行");
        assertEquals(ATTEMPTS - 3, limited, "其余并发请求必须全部稳定拒绝");
    }

    /**
     * 同一客户端的两个 scope 各 3 个名额；32+32 个请求交叉并发，
     * 两边都必须恰好放过 3 个——跨范围计数不能互相串。
     */
    @Test
    void concurrentRequestsAcrossScopesDoNotMixCounters() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(ATTEMPTS * 2);
        CountDownLatch ready = new CountDownLatch(ATTEMPTS * 2);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> futures = new ArrayList<>();

        for (int i = 0; i < ATTEMPTS; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                HttpResponse<String> r = signed("client-edge-3", SECRET_EDGE_3)
                        .path("/api/orders/ping")
                        .body("{}")
                        .nonce("edge3-ping-" + UUID.randomUUID())
                        .send();
                return "ping:" + r.statusCode();
            }));
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                HttpResponse<String> r = signed("client-edge-3", SECRET_EDGE_3)
                        .path("/api/orders/list")
                        .body("{}")
                        .nonce("edge3-read-" + UUID.randomUUID())
                        .send();
                return "read:" + r.statusCode();
            }));
        }

        ready.await();
        start.countDown();

        int pingOk = 0;
        int pingLimited = 0;
        int readOk = 0;
        int readLimited = 0;
        for (Future<String> f : futures) {
            String result = f.get();
            String scope = result.substring(0, result.indexOf(':'));
            int status = Integer.parseInt(result.substring(result.indexOf(':') + 1));
            if (scope.equals("ping")) {
                if (status == 200) {
                    pingOk++;
                } else if (status == 429) {
                    pingLimited++;
                } else {
                    throw new AssertionError("ping 意外状态码：" + status);
                }
            } else {
                if (status == 200) {
                    readOk++;
                } else if (status == 429) {
                    readLimited++;
                } else {
                    throw new AssertionError("read 意外状态码：" + status);
                }
            }
        }
        pool.shutdown();

        assertEquals(3, pingOk, "orders:ping 独立计数，恰好 3 个");
        assertEquals(ATTEMPTS - 3, pingLimited);
        assertEquals(3, readOk, "orders:read 独立计数，恰好 3 个");
        assertEquals(ATTEMPTS - 3, readLimited);
    }
}
