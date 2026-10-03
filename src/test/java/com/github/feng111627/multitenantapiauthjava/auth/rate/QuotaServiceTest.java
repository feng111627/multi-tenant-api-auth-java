package com.github.feng111627.multitenantapiauthjava.auth.rate;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link QuotaService} 令牌桶行为的纯单元测试。
 *
 * <p>使用 {@link ManualClock} 让时间只随测试显式推进，因此突发、补充与回收的
 * 判定完全确定、可反复复现，不依赖墙钟与线程调度时序。</p>
 */
class QuotaServiceTest {

    private static final long WINDOW = 60_000L;

    private boolean acquire(QuotaService quota, String client, String scope) {
        // rate=3/窗口，burst=5：稳态 3、突发余量额外 2
        return quota.tryAcquire(client, scope, 3, 5, WINDOW);
    }

    @Test
    void burstCapacityIsAllowedAndBoundaryIsStable() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 桶初始为满：突发 5 个必须整波放行
        for (int i = 1; i <= 5; i++) {
            assertTrue(acquire(quota, "c", "orders:read"),
                    "突发第 " + i + " 个请求应在突发容量内放行");
        }
        // 突发见底：同一时刻第 6 个必须拒绝
        assertFalse(acquire(quota, "c", "orders:read"),
                "超过突发上限的下一个请求必须拒绝");
        // 时间不推进，再试仍然拒绝，结果可稳定复现
        assertFalse(acquire(quota, "c", "orders:read"));
    }

    @Test
    void tokensRecoverSmoothlyInsteadOfReleasingInOneBatch() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        for (int i = 0; i < 5; i++) {
            assertTrue(acquire(quota, "c", "orders:read"));
        }
        assertFalse(acquire(quota, "c", "orders:read"));

        // 稳态速率 3/窗口：差 1ms 不到一个令牌的补充时间（20s/个），不放行
        clock.advance(19_999L);
        assertFalse(acquire(quota, "c", "orders:read"),
                "不足一个令牌的补充时间时不应放行，避免提前抖动");

        // 恰好一个令牌的时间：只放行 1 个，下一个仍被拒（匀速回收，不是成片放开）
        clock.advance(1L);
        assertTrue(acquire(quota, "c", "orders:read"), "补充出 1 个令牌应放行");
        assertFalse(acquire(quota, "c", "orders:read"),
                "只补充了 1 个令牌，下一个必须继续拒绝");

        // 再经过一个完整窗口：补充 3 个令牌（桶里此时为 3），只能连续放行 3 个
        clock.advance(WINDOW);
        for (int i = 0; i < 3; i++) {
            assertTrue(acquire(quota, "c", "orders:read"),
                    "一个窗口只匀速补充 3 个，应逐个放行 " + i);
        }
        assertFalse(acquire(quota, "c", "orders:read"),
                "第 4 个必须拒绝：突发余量不会在一个窗口内瞬间回满");

        // 关键：持续压测时吞吐收敛到稳态速率，而不是反复"憋住→成片放开"。
        // 每个完整窗口恰好匀速补 3 个，跨多个窗口稳定保持 3/窗口。
        for (int window = 0; window < 3; window++) {
            clock.advance(WINDOW);
            for (int i = 0; i < 3; i++) {
                assertTrue(acquire(quota, "c", "orders:read"),
                        "第 " + window + " 窗口第 " + i + " 个稳态请求应放行");
            }
            assertFalse(acquire(quota, "c", "orders:read"),
                    "稳态窗口内第 4 个请求必须被拒绝");
        }

        // 长时间空闲后令牌也只能封顶到突发容量 5，不会无限堆积后一次性放开
        clock.advance(WINDOW * 100);
        int allowed = 0;
        for (int i = 0; i < 10; i++) {
            if (acquire(quota, "c", "orders:read")) {
                allowed++;
            }
        }
        assertEquals(5, allowed, "空闲再久，令牌也封顶在突发容量，不能一次性放开一大片");
    }

    @Test
    void concurrentRequestsAtBoundaryHaveDeterministicWinnerCount() throws Exception {
        // 时间全程冻结：24 个线程在同一毫秒争抢 burst=5 的桶，
        // 必须恰好 5 个成功、19 个失败，与调度无关，重跑一致。
        for (int run = 0; run < 5; run++) {
            ManualClock clock = new ManualClock();
            QuotaService quota = new QuotaService(clock);
            int threads = 24;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDown start = new CountDown(threads);
            List<Future<Boolean>> futures = new ArrayList<>();

            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.arrive();
                    start.awaitRelease();
                    // 加一点随机 park，制造更激烈的临界竞争
                    LockSupport.parkNanos((long) (Math.random() * 50_000));
                    return acquire(quota, "c", "orders:read");
                }));
            }
            start.awaitAllReady();
            start.release();

            int accepted = 0;
            for (Future<Boolean> f : futures) {
                if (f.get()) {
                    accepted++;
                }
            }
            pool.shutdown();
            assertEquals(5, accepted,
                    "第 " + run + " 轮：突发见底并发压界必须恰好放行 5 个");
        }
    }

    @Test
    void quotaIsIsolatedPerClient() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        for (int i = 0; i < 5; i++) {
            assertTrue(acquire(quota, "client-limited", "orders:read"));
        }
        assertFalse(acquire(quota, "client-limited", "orders:read"));

        // 另一个客户端的桶完全独立，照常拥有完整容量
        assertTrue(acquire(quota, "client-a", "orders:read"));
    }

    @Test
    void scopesOfSameClientDoNotInterfere() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 把 read 范围的桶打满（注意：两个范围配置不同配额）
        for (int i = 0; i < 5; i++) {
            assertTrue(quota.tryAcquire("c", "orders:read", 3, 5, WINDOW));
        }
        assertFalse(quota.tryAcquire("c", "orders:read", 3, 5, WINDOW),
                "orders:read 已见底");

        // export 范围有自己独立的桶与配额，不受 read 见底影响
        for (int i = 0; i < 10; i++) {
            assertTrue(quota.tryAcquire("c", "orders:export", 10, 10, WINDOW),
                    "orders:export 必须独立计数，不应被 orders:read 挤占");
        }

        // 反过来：export 见底也不影响 read 的回收节奏
        clock.advance(WINDOW);
        int readAllowed = 0;
        for (int i = 0; i < 5; i++) {
            if (quota.tryAcquire("c", "orders:read", 3, 5, WINDOW)) {
                readAllowed++;
            }
        }
        assertEquals(3, readAllowed, "read 范围只按自己的稳态速率回收");
    }

    @Test
    void compositeKeyCanNeverCollideAcrossClientAndScopePairs() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 四个不同的 (clientId, scope) 组合，其字符串拼接形式存在相互包含/歧义，
        // 借助内部分隔符必须仍是四个互不影响的独立桶（容量均为 1）。
        String[][] pairs = {
                {"a", "b:c"},
                {"a:b", "c"},
                {"a", "b"},
                {"a:b:c", ""},
        };
        for (String[] pair : pairs) {
            assertTrue(quota.tryAcquire(pair[0], pair[1], 1, 1, WINDOW),
                    "组合 (" + pair[0] + "," + pair[1] + ") 应拿到属于自己的桶并放行");
        }
        for (String[] pair : pairs) {
            assertFalse(quota.tryAcquire(pair[0], pair[1], 1, 1, WINDOW),
                    "组合 (" + pair[0] + "," + pair[1] + ") 自己的桶应已见底，不能落到他人桶上");
        }
    }

    @Test
    void zeroRateWithoutBurstRejectsEverything() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);
        assertFalse(quota.tryAcquire("c", "orders:read", 0, 0, WINDOW));
        clock.advance(WINDOW * 10);
        assertFalse(quota.tryAcquire("c", "orders:read", 0, 0, WINDOW),
                "速率与突发都为 0 时，任何时刻都不放行");
    }

    /**
     * 极简起跑门：所有线程就绪后由主线程一次性释放。
     */
    private static final class CountDown {
        private final Object lock = new Object();
        private int ready;
        private boolean released;

        CountDown(int parties) {
            this.ready = parties;
        }

        void arrive() {
            synchronized (lock) {
                ready--;
                lock.notifyAll();
            }
        }

        void awaitRelease() throws InterruptedException {
            synchronized (lock) {
                while (!released) {
                    lock.wait();
                }
            }
        }

        void awaitAllReady() throws InterruptedException {
            synchronized (lock) {
                while (ready > 0) {
                    lock.wait();
                }
            }
        }

        void release() {
            synchronized (lock) {
                released = true;
                lock.notifyAll();
            }
        }
    }
}
