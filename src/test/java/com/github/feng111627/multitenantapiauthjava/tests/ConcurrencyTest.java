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
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发请求测试：两个客户端在同一时刻交叉请求，
 * 验证身份（ThreadLocal）与数据归属（owner 过滤）都不串号。
 */
class ConcurrencyTest extends AbstractApiIntegrationTest {

    private static final int THREADS_PER_CLIENT = 24;

    @Test
    void concurrentRequestsFromTwoClientsNeverLeakAcross() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS_PER_CLIENT * 2);
        CountDownLatch ready = new CountDownLatch(THREADS_PER_CLIENT * 2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger checked = new AtomicInteger();

        List<Future<Void>> futures = new ArrayList<>();

        for (int i = 0; i < THREADS_PER_CLIENT; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                // client-a 查 tenant-a 的订单，响应里绝不能出现 tenant-b
                HttpResponse<String> response = signed("client-a", SECRET_A)
                        .path("/api/orders/list")
                        .nonce("conc-a-" + UUID.randomUUID())
                        .body("{}")
                        .send();
                checked.incrementAndGet();
                assertEquals(200, response.statusCode());
                assertTrue(response.body().contains("ORD-1001"));
                assertFalse(response.body().contains("tenant-b"),
                        "client-a 的并发响应串入了 tenant-b 数据：" + response.body());
                assertFalse(response.body().contains("ORD-200"),
                        "client-a 的并发响应串入了 B 的订单：" + response.body());
                return null;
            }));

            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                // client-b 查自己的订单，响应里绝不能出现 tenant-a
                HttpResponse<String> response = signed("client-b", SECRET_B)
                        .path("/api/orders/list")
                        .nonce("conc-b-" + UUID.randomUUID())
                        .body("{}")
                        .send();
                checked.incrementAndGet();
                assertEquals(200, response.statusCode());
                assertTrue(response.body().contains("ORD-2001"));
                assertFalse(response.body().contains("tenant-a"),
                        "client-b 的并发响应串入了 tenant-a 数据：" + response.body());
                assertFalse(response.body().contains("ORD-100"),
                        "client-b 的并发响应串入了 A 的订单：" + response.body());
                return null;
            }));
        }

        ready.await();
        start.countDown(); // 同时释放所有线程，最大化请求交叉

        for (Future<Void> future : futures) {
            future.get();
        }
        pool.shutdown();

        assertEquals(THREADS_PER_CLIENT * 2, checked.get());
    }

    @Test
    void concurrentSameNonceOnlyOneSucceeds() throws Exception {
        // 同一客户端、同一 nonce 并发提交：有且仅有一个能通过重放检测
        String nonce = "race-nonce-" + UUID.randomUUID();
        int attempts = 16;
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        CountDownLatch ready = new CountDownLatch(attempts);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();

        for (int i = 0; i < attempts; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                HttpResponse<String> response = signed("client-a", SECRET_A)
                        .body("{\"orderId\":\"ORD-1001\"}")
                        .nonce(nonce)
                        .send();
                return response.statusCode();
            }));
        }

        ready.await();
        start.countDown();

        int accepted = 0;
        int replayed = 0;
        for (Future<Integer> future : futures) {
            int status = future.get();
            if (status == 200) {
                accepted++;
            } else if (status == 409) {
                replayed++;
            } else {
                throw new AssertionError("意外的状态码：" + status);
            }
        }
        pool.shutdown();

        assertEquals(1, accepted, "相同 nonce 并发提交只能有一个请求通过");
        assertEquals(attempts - 1, replayed, "其余请求必须全部判定为重放");
    }
}
