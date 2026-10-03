package com.github.feng111627.multitenantapiauthjava.tests;

import com.github.feng111627.multitenantapiauthjava.tests.support.AbstractApiIntegrationTest;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 突发余量集成测试（client-burst：稳态 2/窗口、突发上限 5）。
 *
 * <p>为避免依赖墙钟睡眠，本类只断言与墙钟无关的稳定性质：
 * 突发整波放行、并发压界恰好放满突发容量、见底后在同一时刻持续被拒。
 * 随时间平滑回收到稳态速率的完整性质由 {@code QuotaServiceTest} 用可控时钟确定性覆盖。</p>
 */
class BurstQuotaIntegrationTest extends AbstractApiIntegrationTest {

    private HttpResponse<String> call() throws Exception {
        return signed("client-burst", SECRET_BURST)
                .path("/api/orders/list").body("{}").send();
    }

    @Test
    void shortBurstIsFullyAllowedThenRejectedAtTheBoundary() throws Exception {
        // 突发 5 个整波放行（都在同一窗口瞬间到达）
        for (int i = 1; i <= 5; i++) {
            assertEquals(200, call().statusCode(), "突发第 " + i + " 个应整波放行");
        }
        // 第 6 个越过突发上限，必须 429
        assertEquals(429, call().statusCode(), "突发见底，下一个必须被拒");
        // 连续再来两个，同一时刻桶不会无中生有，结果稳定
        assertEquals(429, call().statusCode());
        assertEquals(429, call().statusCode());
    }

    @Test
    void concurrentBurstBoundaryAllowsExactlyTheCapacity() throws Exception {
        // 24 个线程在同一时刻争抢 burst=5 的桶，必须恰好 5 个 200、19 个 429。
        // 多跑几轮，验证结果与线程调度无关、可稳定复现。
        for (int run = 0; run < 3; run++) {
            // 每轮独立：重置桶，保证每轮都从满突发容量开始压界
            quotaService.reset();
            int threads = 24;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Integer>> futures = new ArrayList<>();

            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    LockSupport.parkNanos((long) (Math.random() * 50_000));
                    return call().statusCode();
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

            assertEquals(5, ok, "第 " + run + " 轮：并发压界必须恰好放行突发容量 5");
            assertEquals(threads - 5, limited);
        }
    }
}
