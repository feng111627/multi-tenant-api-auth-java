package com.github.feng111627.multitenantapiauthjava.auth.rate;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 按"客户端 + 接口范围"维度的令牌桶限流器。
 *
 * <p>每个 (clientId, scope) 持有一个独立桶，互不挤占：</p>
 * <ul>
 *     <li>稳态补充速率 = {@code rateLimit / windowMillis}（每窗口补充 rateLimit 个令牌）；</li>
 *     <li>桶容量 = {@code rateLimit + burst}，即稳态额度之上额外允许 burst 个突发请求；</li>
 *     <li>令牌按经过的时间平滑回收补充，因此突发用完后会自动回到稳态速率，
 *     不会出现"长时间全拒、窗口切换时一次性放开"的抖动；</li>
 *     <li>桶初始为满，{@code burst=0} 时容量恰为稳态额度。</li>
 * </ul>
 *
 * <p>确定性：令牌数用 {@link #SCALE} 整数放大保存，全程整数运算，不存在浮点误差；
 * 单个桶的"补充 + 扣减"在同一个 synchronized 块内完成，并发压到边界时
 * 恰好最后一个放行、其后全部拒绝，重跑结果一致。不同 scope 是不同的桶、不同的锁，
 * 并发计数不会互相串。</p>
 */
@Component
public class ScopeTokenBucketLimiter {

    /** 令牌的整数放大倍数：保存 1/SCALE 个令牌的精度，避免浮点运算。 */
    static final long SCALE = 1_000_000L;

    private final LongSupplier clockMillis;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public ScopeTokenBucketLimiter() {
        this(System::currentTimeMillis);
    }

    /** 测试用构造器：可注入固定时钟，稳定复现突发与回收过程。 */
    public ScopeTokenBucketLimiter(LongSupplier clockMillis) {
        this.clockMillis = clockMillis;
    }

    /**
     * 在指定客户端的指定范围上尝试占用一个请求名额。
     *
     * @param clientId     客户端标识
     * @param scope        接口范围（不同范围各算各的账）
     * @param rateLimit    稳态额度：每个窗口补充的令牌数（必须为正）
     * @param burst        突发余量：稳态额度之上的额外容量（不小于 0）
     * @param windowMillis 稳态补充窗口长度（毫秒，必须为正）
     * @return 判定结果，remaining 为本次判定后剩余的整令牌数（下取整）
     */
    public QuotaDecision tryAcquire(String clientId, String scope,
                                    long rateLimit, long burst, long windowMillis) {
        if (rateLimit <= 0 || windowMillis <= 0) {
            return new QuotaDecision(false, 0, scope, QuotaDecision.BUCKET_SCOPE, 0, 0);
        }
        long safeBurst = Math.max(0, burst);
        long capacityScaled = Math.multiplyExact(rateLimit + safeBurst, SCALE);

        String key = clientId + ' ' + (scope == null ? "-" : scope);
        Bucket bucket = buckets.computeIfAbsent(key,
                k -> new Bucket(capacityScaled, clockMillis.getAsLong()));

        BucketResult result =
                bucket.tryAcquire(rateLimit, windowMillis, capacityScaled, clockMillis.getAsLong());
        return new QuotaDecision(result.allowed(), result.remaining(),
                scope, QuotaDecision.BUCKET_SCOPE, rateLimit, safeBurst);
    }

    /** 桶内部判定结果（不含归属信息，归属由外层补全）。 */
    private record BucketResult(boolean allowed, long remaining) {
    }

    /** 单个 (clientId, scope) 的桶状态；所有状态变更都在桶对象自身的锁内完成。 */
    private static final class Bucket {

        private long tokensScaled;
        private long lastRefillMillis;

        private Bucket(long tokensScaled, long lastRefillMillis) {
            this.tokensScaled = tokensScaled;
            this.lastRefillMillis = lastRefillMillis;
        }

        private synchronized BucketResult tryAcquire(long rateLimit, long windowMillis,
                                                     long capacityScaled, long now) {
            refill(rateLimit, windowMillis, capacityScaled, now);

            if (tokensScaled >= SCALE) {
                tokensScaled -= SCALE;
                return new BucketResult(true, tokensScaled / SCALE);
            }
            // 剩余不足一个整令牌：拒绝。子令牌余量保留在桶里继续参与后续补充，
            // 不四舍五入，保证临界判定稳定、可重放。
            return new BucketResult(false, 0);
        }

        /**
         * 按经过时间补充令牌。补充量用整数精确计算（BigInteger 防乘法溢出），
         * 不足一个最小单位的余量保留在放大整数中，补充后更新时间锚点。
         */
        private void refill(long rateLimit, long windowMillis, long capacityScaled, long now) {
            long elapsed = now - lastRefillMillis;
            if (elapsed <= 0) {
                // 时钟回拨或同毫秒并发：不补充，也不回退已有令牌
                if (tokensScaled > capacityScaled) {
                    tokensScaled = capacityScaled;
                }
                return;
            }
            // earnedScaled = elapsed * rateLimit * SCALE / windowMillis（整除后下取整）
            BigInteger earned = BigInteger.valueOf(elapsed)
                    .multiply(BigInteger.valueOf(rateLimit))
                    .multiply(BigInteger.valueOf(SCALE))
                    .divide(BigInteger.valueOf(windowMillis));

            long addition = Math.min(earned.longValueExact(), capacityScaled);
            long newTokens = tokensScaled + addition;
            tokensScaled = Math.min(newTokens, capacityScaled);
            lastRefillMillis = now;
        }
    }
}
