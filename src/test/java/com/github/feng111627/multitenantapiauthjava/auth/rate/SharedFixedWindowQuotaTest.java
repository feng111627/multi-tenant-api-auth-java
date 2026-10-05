package com.github.feng111627.multitenantapiauthjava.auth.rate;

import org.junit.jupiter.api.DisplayName;
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
 * 老配置（只配 rate-limit、不配突发余量）默认配额的共享固定窗口单元测试。
 *
 * <p>这些用例锁定"按接口范围拆分配额"上线前的计量语义，保证老客户端升级后
 * 行为逐点一致：</p>
 * <ul>
 *     <li>整个客户端共用一份窗口计数，每个窗口严格最多放行 limit 个；</li>
 *     <li>窗口内不会多放一批（不像令牌桶会随时间匀速渗出），窗口期满后
 *         下一个请求立即拿到完整新窗口，不会一直卡着不放；</li>
 *     <li>同一批请求在相同时间点重跑，放行/拒绝序列完全一致、可稳定复现。</li>
 * </ul>
 *
 * <p>使用 {@link ManualClock} 让时间只随测试显式推进，判定完全确定。</p>
 */
class SharedFixedWindowQuotaTest {

    private static final long WINDOW = 60_000L;
    private static final long LIMIT = 3L;

    @Test
    @DisplayName("固定窗口：每窗口严格 limit 个，中途不渗出，期满立即开新窗口")
    void exactlyLimitPerWindowNoTrickleNoStall() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 窗口内前 limit 个放行，第 limit+1 个拒绝
        for (int i = 1; i <= LIMIT; i++) {
            assertTrue(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW),
                    "窗口内第 " + i + " 个请求应放行");
        }
        assertFalse(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW),
                "第 " + (LIMIT + 1) + " 个必须拒绝");

        // 关键差异（相对令牌桶）：窗口未期满时，时间推进不会"渗出"新名额——
        // 老固定窗口在窗口中途一个都不多放
        clock.advance(WINDOW / 2);
        assertFalse(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW),
                "窗口过半但未期满，不允许额外放行（不多放一批）");
        clock.advance(WINDOW / 2 - 1);
        assertFalse(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW),
                "距期满还差 1ms，仍必须拒绝");

        // 窗口期满：下一个请求立即开启新窗口，完整 limit 个立即可用（不会卡着不放）
        clock.advance(1);
        for (int i = 1; i <= LIMIT; i++) {
            assertTrue(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW),
                    "新窗口第 " + i + " 个请求应放行");
        }
        assertFalse(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW),
                "新窗口第 " + (LIMIT + 1) + " 个必须拒绝");
    }

    @Test
    @DisplayName("固定窗口：连续多个窗口稳态放行量恒为 limit/窗口，与拆分前一致")
    void steadyStateMatchesPreSplitFixedWindow() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        // 模拟"持续有请求压着"的稳态：每个窗口打 limit+2 个，恰好 limit 个放行
        for (int window = 0; window < 5; window++) {
            int allowed = 0;
            for (int i = 0; i < LIMIT + 2; i++) {
                if (quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW)) {
                    allowed++;
                }
            }
            assertEquals(LIMIT, allowed,
                    "第 " + window + " 个窗口稳态放行量必须恒为 " + LIMIT);
            clock.advance(WINDOW);
        }
    }

    @Test
    @DisplayName("固定窗口：同一时间序列重跑两次，放行/拒绝序列完全一致")
    void sameTimelineReplaysIdentically() {
        // 构造一条跨 3 个窗口、含窗口边界的时间序列
        long[] timeline = new long[24];
        ManualClock probe = new ManualClock();
        for (int i = 0; i < timeline.length; i++) {
            timeline[i] = probe.millis();
            // 前 8 个在同一毫秒内（突发），之后每次推进 1/4 窗口，自然跨过窗口边界
            probe.advance(i < 7 ? 0 : WINDOW / 4);
        }

        List<Boolean> first = runTimeline(timeline);
        List<Boolean> second = runTimeline(timeline);
        assertEquals(first, second,
                "同一批请求在相同时间点重跑，放行/拒绝结果必须完全一样");

        // 顺带校验内容本身符合固定窗口语义：前 limit 个放行、其后同窗口全拒
        for (int i = 0; i < LIMIT; i++) {
            assertTrue(first.get(i), "突发第 " + i + " 个应放行");
        }
        for (int i = (int) LIMIT; i < 8; i++) {
            assertFalse(first.get(i), "同一窗口内第 " + i + " 个应拒绝");
        }
    }

    private static List<Boolean> runTimeline(long[] timeline) {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);
        List<Boolean> results = new ArrayList<>();
        long previous = clock.millis();
        for (long t : timeline) {
            clock.advance(t - previous);
            previous = t;
            results.add(quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW));
        }
        return results;
    }

    @Test
    @DisplayName("固定窗口：并发压到边界，恰好 limit 个放行、其余拒绝，多轮结果一致")
    void concurrentBoundaryAllowsExactlyLimit() throws Exception {
        // 时间全程冻结：24 个线程在同一毫秒争抢 limit=3 的窗口，
        // 必须恰好 3 个成功、21 个失败，与调度无关，重跑一致。
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
                    LockSupport.parkNanos((long) (Math.random() * 50_000));
                    return quota.tryAcquireSharedFixedWindow("c", LIMIT, WINDOW);
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
            assertEquals(LIMIT, accepted,
                    "第 " + run + " 轮：并发压界必须恰好放行 " + LIMIT + " 个");
        }
    }

    @Test
    @DisplayName("固定窗口：按客户端隔离，且与令牌桶状态互不影响")
    void isolatedPerClientAndFromTokenBuckets() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);

        for (int i = 0; i < LIMIT; i++) {
            assertTrue(quota.tryAcquireSharedFixedWindow("c1", LIMIT, WINDOW));
        }
        assertFalse(quota.tryAcquireSharedFixedWindow("c1", LIMIT, WINDOW),
                "c1 窗口已用尽");

        // 另一个客户端有自己独立的窗口
        assertTrue(quota.tryAcquireSharedFixedWindow("c2", LIMIT, WINDOW),
                "c2 的窗口必须独立，不受 c1 用尽影响");

        // 同名客户端的令牌桶（分范围配额路径）是另一套状态，互不串账
        assertTrue(quota.tryAcquire("c1", "orders:read", 1, 1, WINDOW),
                "c1 的令牌桶与固定窗口是两套独立状态");
    }

    @Test
    @DisplayName("固定窗口：limit=0 永不放行")
    void zeroLimitRejectsEverything() {
        ManualClock clock = new ManualClock();
        QuotaService quota = new QuotaService(clock);
        assertFalse(quota.tryAcquireSharedFixedWindow("c", 0, WINDOW));
        clock.advance(WINDOW * 10);
        assertFalse(quota.tryAcquireSharedFixedWindow("c", 0, WINDOW),
                "限额为 0 时，任何时刻、跨多少窗口都不放行");
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
