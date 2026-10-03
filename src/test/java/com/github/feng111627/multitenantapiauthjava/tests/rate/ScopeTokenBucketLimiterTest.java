package com.github.feng111627.multitenantapiauthjava.tests.rate;

import com.github.feng111627.multitenantapiauthjava.auth.rate.QuotaDecision;
import com.github.feng111627.multitenantapiauthjava.auth.rate.ScopeTokenBucketLimiter;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ScopeTokenBucketLimiter} 纯单元测试：注入可控时钟，
 * 不依赖真实时间流逝，因此突发/回收/临界判定都可稳定复现。
 */
class ScopeTokenBucketLimiterTest {

    private static final long WINDOW = 60_000L;

    private ControlledLimiter limiter() {
        AtomicLong now = new AtomicLong(1_000_000L);
        return new ControlledLimiter(new ScopeTokenBucketLimiter(now::get), now);
    }

    private record ControlledLimiter(ScopeTokenBucketLimiter limiter, AtomicLong now) {

        QuotaDecision acquire(String client, String scope, long rate, long burst) {
            return limiter.tryAcquire(client, scope, rate, burst, WINDOW);
        }

        void advance(long millis) {
            now.addAndGet(millis);
        }
    }

    @Test
    void burstAllowsOneWaveAboveSteadyRate() {
        ControlledLimiter c = limiter();
        // rate=2, burst=2：桶容量 4，可一次性放行 4 个
        for (int i = 1; i <= 4; i++) {
            QuotaDecision d = c.acquire("c1", "orders:read", 2, 2);
            assertTrue(d.allowed(), "突发波第 " + i + " 个请求应放行");
            assertEquals(QuotaDecision.BUCKET_SCOPE, d.bucketType());
            assertEquals("orders:read", d.scope());
        }
        // 第 5 个立刻到来：桶已见底，必须拒绝
        QuotaDecision rejected = c.acquire("c1", "orders:read", 2, 2);
        assertFalse(rejected.allowed());
        assertEquals(0, rejected.remaining());
    }

    @Test
    void drainedBucketRefillsSmoothlyBackToSteadyRate() {
        ControlledLimiter c = limiter();
        // 一波 4 个见底（rate=2, burst=2）
        for (int i = 0; i < 4; i++) {
            assertTrue(c.acquire("c1", "orders:read", 2, 2).allowed());
        }
        assertFalse(c.acquire("c1", "orders:read", 2, 2).allowed());

        // 过半个窗口：按 2/60s 的速率应恰好补回 1 个令牌
        c.advance(WINDOW / 2);
        assertTrue(c.acquire("c1", "orders:read", 2, 2).allowed(),
                "半个窗口后应平滑补回 1 个令牌");
        assertFalse(c.acquire("c1", "orders:read", 2, 2).allowed(),
                "补回的 1 个用掉后，不能再放行（未到下一补充时刻）");

        // 再过半个窗口：又补回 1 个
        c.advance(WINDOW / 2);
        assertTrue(c.acquire("c1", "orders:read", 2, 2).allowed());

        // 经过完整窗口后稳态回到每窗口 2 个的速率，且不会一次性放开一大片
        c.advance(WINDOW);
        assertTrue(c.acquire("c1", "orders:read", 2, 2).allowed());
        assertTrue(c.acquire("c1", "orders:read", 2, 2).allowed());
        assertFalse(c.acquire("c1", "orders:read", 2, 2).allowed(),
                "稳态下第 3 个必须拒绝，突发余量已被之前的波次消耗");
    }

    @Test
    void refillNeverOpensABigBatchAtOnce() {
        ControlledLimiter c = limiter();
        for (int i = 0; i < 3; i++) {
            assertTrue(c.acquire("c1", "orders:ping", 3, 0).allowed());
        }
        assertFalse(c.acquire("c1", "orders:ping", 3, 0).allowed());

        // 1/6 窗口约补 0.5 个令牌，不足一个整令牌：拒绝（不提前放行）
        c.advance(WINDOW / 6);
        assertFalse(c.acquire("c1", "orders:ping", 3, 0).allowed());

        // 再走 1/6 窗口：累计约 1 个令牌，恰好放出 1 个，紧接着的请求必须被拒
        c.advance(WINDOW / 6);
        assertTrue(c.acquire("c1", "orders:ping", 3, 0).allowed(),
                "累计足够时间后应只平滑放出 1 个");
        assertFalse(c.acquire("c1", "orders:ping", 3, 0).allowed(),
                "只补了 1 个，第 2 个不能跟着放行，不能一次性放开一大片");
    }

    @Test
    void boundaryDecisionIsStableAcrossRuns() {
        // 同参数、同操作序列跑多遍，结果必须逐位一致
        for (int run = 0; run < 20; run++) {
            ControlledLimiter c = limiter();
            for (int i = 0; i < 5; i++) {
                boolean expected = i < 3; // rate=3, burst=0：恰好 3 个
                QuotaDecision d = c.acquire("edge", "orders:ping", 3, 0);
                assertEquals(expected, d.allowed(),
                        "run=" + run + " i=" + i + " 临界判定不稳定");
            }
        }
    }

    @Test
    void differentScopesAndClientsNeverShareTokens() {
        ControlledLimiter c = limiter();
        // 把 client-a 的 orders:read 打空（容量 2）
        assertTrue(c.acquire("client-a", "orders:read", 2, 0).allowed());
        assertTrue(c.acquire("client-a", "orders:read", 2, 0).allowed());
        assertFalse(c.acquire("client-a", "orders:read", 2, 0).allowed());

        // 同一客户端的另一个 scope 仍然是满桶
        assertTrue(c.acquire("client-a", "orders:ping", 2, 0).allowed());
        // 另一个客户端的同名 scope 也仍然是满桶
        assertTrue(c.acquire("client-b", "orders:read", 2, 0).allowed());
        assertTrue(c.acquire("client-b", "orders:read", 2, 0).allowed());
        assertFalse(c.acquire("client-b", "orders:read", 2, 0).allowed());
    }

    @Test
    void burstZeroBehavesAsSteadyCapacityOnly() {
        ControlledLimiter c = limiter();
        for (int i = 1; i <= 2; i++) {
            assertTrue(c.acquire("c", "s", 2, 0).allowed());
        }
        assertFalse(c.acquire("c", "s", 2, 0).allowed());
        // 同毫秒重试：时钟未前进，仍拒绝（不会抖动放行）
        assertFalse(c.acquire("c", "s", 2, 0).allowed());
    }
}
