package com.github.feng111627.multitenantapiauthjava.auth.rate;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * 老配置（只配 {@code rate-limit}、不配突发余量）固定窗口计量的纯单元测试。
 *
 * <p>覆盖"窗口一致性"回归：拆分前老客户端每个窗口严格放行 {@code limit} 个、
 * 窗口期满立即恢复全量。修复前这类客户端被错误地套用了"初始满桶 + 匀速渗入"的
 * 令牌桶，首窗口最多能放出接近两倍的量（多放一批），而桶见底后窗口切换时又不
 * 整体重置、只能等令牌慢慢攒（另一段时间一直卡着不放）。</p>
 *
 * <p>使用 {@link ManualClock} 让时间只随测试显式推进，因此所有判定完全确定、
 * 可反复复现，不依赖墙钟与线程调度时序。</p>
 */
class FixedWindowQuotaTest {

    private static final Logger log = LoggerFactory.getLogger(FixedWindowQuotaTest.class);

    private static final long WINDOW = 60_000L;

    private boolean acquire(QuotaService quota, String client, String scope) {
        // 老配置语义：每窗口 3 个，固定窗口
        return quota.tryAcquireFixedWindow(client, scope, 3, WINDOW);
    }

    @Test
    void exactlyLimitPerWindowAndFullResetAtWindowSwitch() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 第一个窗口：恰好 3 个放行，第 4 个拒绝——首窗口绝不多放一批
        for (int i = 1; i <= 3; i++) {
            assertTrue(acquire(quota, "c", QuotaService.DEFAULT_SCOPE),
                    "首窗口第 " + i + " 个请求应放行");
        }
        assertFalse(acquire(quota, "c", QuotaService.DEFAULT_SCOPE),
                "首窗口第 4 个请求必须拒绝：不能多放一批");

        // 窗口期内任意时刻（含差 1ms 到期）都不再放行
        clock.advance(30_000L);
        assertFalse(acquire(quota, "c", QuotaService.DEFAULT_SCOPE));
        clock.advance(29_999L);
        assertFalse(acquire(quota, "c", QuotaService.DEFAULT_SCOPE),
                "窗口差 1ms 到期时仍应拒绝");

        // 窗口期满：立即恢复完整 3 个额度（整体重置，不是慢慢渗入）
        clock.advance(1L);
        for (int i = 1; i <= 3; i++) {
            assertTrue(acquire(quota, "c", QuotaService.DEFAULT_SCOPE),
                    "窗口切换后第 " + i + " 个请求应立即放行（整体重置，不能卡着不放）");
        }
        assertFalse(acquire(quota, "c", QuotaService.DEFAULT_SCOPE));

        // 稳态：连续多个窗口，每个窗口都严格是 3 个
        for (int window = 0; window < 3; window++) {
            clock.advance(WINDOW);
            for (int i = 1; i <= 3; i++) {
                assertTrue(acquire(quota, "c", QuotaService.DEFAULT_SCOPE),
                        "第 " + window + " 个稳态窗口第 " + i + " 个请求应放行");
            }
            assertFalse(acquire(quota, "c", QuotaService.DEFAULT_SCOPE),
                    "第 " + window + " 个稳态窗口第 4 个请求必须拒绝");
        }
        log.info("固定窗口窗口一致性用例通过：首窗口不多放、期满整体重置、稳态每窗口严格 3 个");
    }

    @Test
    void sameRequestSequenceAtSameTimestampsYieldsIdenticalResults() {
        // 同一批请求、同一时间序列，用全新实例重跑两回，放行/拒绝必须逐位一致
        long[] offsets = {0, 0, 0, 0, 10_000, 20_000, 59_999, 60_000, 60_000, 60_000, 60_000, 119_999, 120_000};
        List<Boolean> firstRun = runSequence(offsets);
        List<Boolean> secondRun = runSequence(offsets);
        assertEquals(firstRun, secondRun,
                "相同时间序列重跑，放行/拒绝结果必须完全一样、可稳定复现");
        log.info("固定窗口可复现性用例通过：{} 个请求的重放结果逐位一致 {}", firstRun.size(), firstRun);
    }

    private List<Boolean> runSequence(long[] offsets) {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);
        List<Boolean> results = new ArrayList<>();
        long previous = 0;
        for (long offset : offsets) {
            clock.advance(offset - previous);
            previous = offset;
            results.add(acquire(quota, "c", QuotaService.DEFAULT_SCOPE));
        }
        return results;
    }

    @Test
    void concurrentRequestsAtWindowBoundaryAllowExactlyTheLimit() throws Exception {
        // 时间全程冻结：24 个线程在同一毫秒争抢 limit=3 的固定窗口，
        // 必须恰好 3 个成功（最后一个放行）、21 个失败（下一个即拒），与调度无关。
        for (int run = 0; run < 5; run++) {
            ManualClock clock = new ManualClock();
            QuotaService quota = new QuotaService(clock);
            int threads = 24;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            QuotaServiceTestGate start = new QuotaServiceTestGate(threads);
            List<Future<Boolean>> futures = new ArrayList<>();

            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.arrive();
                    start.awaitRelease();
                    LockSupport.parkNanos((long) (Math.random() * 50_000));
                    return acquire(quota, "c", QuotaService.DEFAULT_SCOPE);
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
            assertEquals(3, accepted,
                    "第 " + run + " 轮：并发压到窗口临界值必须恰好放行 3 个");
        }
        log.info("固定窗口并发压界用例通过：5 轮 x 24 线程，每轮恰好放行 3 个");
    }

    @Test
    void windowKeysAreIndependentPerClientAndScopeKey() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 同一范围键打满后，另一个范围键（或另一个客户端）不受影响
        for (int i = 0; i < 3; i++) {
            assertTrue(acquire(quota, "c", QuotaService.DEFAULT_SCOPE));
        }
        assertFalse(acquire(quota, "c", QuotaService.DEFAULT_SCOPE));
        assertTrue(acquire(quota, "c", "orders:read"),
                "不同范围键的窗口互不影响");
        assertTrue(acquire(quota, "other", QuotaService.DEFAULT_SCOPE),
                "不同客户端的窗口互不影响");

        // 而同一个 (client, 范围键) 无论调多少次都共享同一个窗口：
        // 调用方把多个具体范围映射到同一个键时，合计自然受同一份额度约束
        assertTrue(quota.tryAcquireFixedWindow("shared", QuotaService.DEFAULT_SCOPE, 3, WINDOW));
        assertTrue(quota.tryAcquireFixedWindow("shared", QuotaService.DEFAULT_SCOPE, 3, WINDOW));
        assertTrue(quota.tryAcquireFixedWindow("shared", QuotaService.DEFAULT_SCOPE, 3, WINDOW));
        assertFalse(quota.tryAcquireFixedWindow("shared", QuotaService.DEFAULT_SCOPE, 3, WINDOW),
                "共享键上的第 4 个请求必须拒绝：合计不能超过同一份默认额度");
    }

    @Test
    void zeroLimitRejectsEverything() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);
        assertFalse(quota.tryAcquireFixedWindow("c", QuotaService.DEFAULT_SCOPE, 0, WINDOW));
        clock.advance(WINDOW * 10);
        assertFalse(quota.tryAcquireFixedWindow("c", QuotaService.DEFAULT_SCOPE, 0, WINDOW),
                "限额为 0 时任何时刻都不放行");
    }

    /**
     * 极简起跑门：所有线程就绪后由主线程一次性释放。
     */
    private static final class QuotaServiceTestGate {
        private final Object lock = new Object();
        private int ready;
        private boolean released;

        QuotaServiceTestGate(int parties) {
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
