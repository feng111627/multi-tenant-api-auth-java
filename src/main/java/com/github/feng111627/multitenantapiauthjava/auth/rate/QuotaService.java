package com.github.feng111627.multitenantapiauthjava.auth.rate;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按「客户端 × 接口范围」维度的配额服务（令牌桶）。
 *
 * <p>每个 {@code (clientId, scope)} 维护一个独立令牌桶：</p>
 * <ul>
 *     <li><b>稳态速率</b>：每 {@code windowMillis} 匀速补充 {@code rateLimit} 个令牌，
 *         因此突发流量过去后会平滑收回到稳态速率，不会出现"长时间不放行、然后成片放开"的抖动；</li>
 *     <li><b>突发余量</b>：桶容量为 {@code burstLimit}，桶初始为满，短时间内最多可一次性
 *         放行 {@code burstLimit} 个请求；</li>
 *     <li><b>互不挤占</b>：不同 scope 使用不同的桶；客户端默认配额与各范围配额分别独立计数。</li>
 * </ul>
 *
 * <p>令牌数以"毫令牌"（令牌 × 1000）的整数保存并做补充运算，避免浮点误差在临界值上
 * 造成判定漂移。单次"补充 → 判定 → 扣减"在桶对象锁内一次完成，因此突发见底时
 * 并发压到边界（最后一个放行、下一个拒绝）的结果与线程调度无关，重跑一致。</p>
 *
 * <p>桶只会在调用方（拦截器）完成身份与签名校验之后创建，scope 键取自服务端注解，
 * 伪造的 clientId/请求参数无法制造桶，桶总数有界。</p>
 */
@Component
public class QuotaService {

    /** 未标注 {@code @RequireScope} 的接口所使用的兜底范围键。 */
    public static final String DEFAULT_SCOPE = "-";

    /** 令牌放大倍数：内部以毫令牌为最小单位，消除浮点误差。 */
    private static final long MILLI = 1000L;

    /** 组合键内部分隔符，选用请求标识中不会出现的控制字符。 */
    private static final char KEY_SEPARATOR = '\u0000';

    private final Clock clock;
    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    public QuotaService() {
        this(Clock.systemUTC());
    }

    QuotaService(Clock clock) {
        this.clock = clock;
    }

    /**
     * 尝试在指定客户端的指定范围上占用一个请求名额。
     *
     * @param clientId     客户端标识（调用方必须已确认该客户端存在且通过校验）
     * @param scope        接口范围（无范围接口用 {@link #DEFAULT_SCOPE}）
     * @param rateLimit    稳态速率（每个窗口补充的令牌数）
     * @param burstLimit   突发上限（桶容量，{@code >= rateLimit} 时留有额外突发余量）
     * @param windowMillis 稳态窗口长度（毫秒）
     * @return true 放行；false 表示该客户端在该范围上的配额已用尽
     */
    public boolean tryAcquire(String clientId, String scope,
                              long rateLimit, long burstLimit, long windowMillis) {
        long now = clock.millis();
        long safeRate = Math.max(rateLimit, 0);
        long safeBurst = Math.max(burstLimit, 0);
        long safeWindow = windowMillis > 0 ? windowMillis : 1L;

        String key = clientId + String.valueOf(KEY_SEPARATOR) + scope;
        // compute 原子建桶：同一 (clientId, scope) 永远拿到同一个桶实例
        TokenBucket bucket = buckets.computeIfAbsent(key,
                k -> new TokenBucket(safeRate, safeBurst, safeWindow, now));

        return bucket.tryConsume(now);
    }

    /**
     * 清空所有桶状态。仅供测试在用例之间重置，保证配额断言不受其它用例残留状态影响。
     */
    public void reset() {
        buckets.clear();
    }

    /**
     * 单个（客户端, 范围）的令牌桶状态。所有可变状态只在 {@code this} 锁内读写。
     */
    private static final class TokenBucket {

        private final long capacityMilli;
        private final long refillMilliPerWindow;
        private final long windowMillis;

        private long tokensMilli;
        private long lastRefillMillis;
        /** 上次补充后不足 1 个令牌的剩余时间（毫秒），跨次累计，消除整除丢尾偏差。 */
        private long carryMillis;

        private TokenBucket(long rateLimit, long burstLimit, long windowMillis, long now) {
            // 桶初始为满：刚启动 / 首次请求即拥有完整突发余量
            this.capacityMilli = burstLimit * MILLI;
            this.refillMilliPerWindow = rateLimit * MILLI;
            this.windowMillis = windowMillis;
            this.tokensMilli = capacityMilli;
            this.lastRefillMillis = now;
            this.carryMillis = 0;
        }

        private boolean tryConsume(long now) {
            synchronized (this) {
                refill(now);
                if (tokensMilli >= MILLI) {
                    tokensMilli -= MILLI;
                    return true;
                }
                return false;
            }
        }

        /**
         * 按经过时间匀速补充令牌并封顶到容量。全程整数（毫令牌）运算，
         * 先乘后除保证：给定相同的时间序列，补充结果逐次相同，不依赖线程调度。
         *
         * <p>不足 1 个令牌的时间零头保存在 {@link #carryMillis} 跨次累计，
         * 不从令牌数反推时间，杜绝取整偏差；令牌封顶到容量后，这段空闲多余的
         * 时间直接作废（下次请求从当前时刻重新计时），因此空闲再久也不会超填。</p>
         */
        private void refill(long now) {
            long elapsed = now - lastRefillMillis;
            if (elapsed <= 0) {
                return;
            }
            if (refillMilliPerWindow == 0) {
                // rateLimit=0：永不补充
                tokensMilli = 0;
                lastRefillMillis = now;
                carryMillis = 0;
                return;
            }

            long totalMillis = carryMillis + elapsed;
            // 钳制本次可用于补充的时间：超过"灌满所需时间"的部分会作废，
            // 同时避免 totalMillis * refillMilliPerWindow 乘法溢出
            long roomMilli = capacityMilli - tokensMilli;
            long fillDuration = roomMilli > 0
                    ? roomMilli * windowMillis / refillMilliPerWindow : 0;
            long effectiveMillis = Math.min(totalMillis, fillDuration);

            long addedMilli = effectiveMillis * refillMilliPerWindow / windowMillis;
            tokensMilli = Math.min(capacityMilli, tokensMilli + addedMilli);

            if (tokensMilli >= capacityMilli) {
                // 已灌满：剩余空闲时间作废，从当前时刻重新累计，保证封顶不超填
                lastRefillMillis = now;
                carryMillis = 0;
            } else {
                // 未灌满：记录"折算时间 + 零头"，保留不足 1 令牌的余量到下一次
                long consumedMillis = addedMilli * windowMillis / refillMilliPerWindow;
                carryMillis = totalMillis - consumedMillis;
                lastRefillMillis = now;
            }
        }
    }
}
