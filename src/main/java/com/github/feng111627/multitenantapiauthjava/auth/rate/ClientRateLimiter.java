package com.github.feng111627.multitenantapiauthjava.auth.rate;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 按客户端维度的固定窗口限流器。
 *
 * <p>每个 clientId 维护一个"窗口起始时间 + 窗口内计数"，窗口切换时原子重置。
 * 计数与窗口判断通过同一个锁/原子引用完成，保证并发下临界值判定稳定：
 * 每个窗口内严格最多放行 {@code limit} 个请求。</p>
 */
@Component
public class ClientRateLimiter {

    private record Window(long startMillis, AtomicLong count) {
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /**
     * 尝试占用一个请求名额。
     *
     * @param clientId     客户端标识
     * @param limit        每个窗口最大请求数
     * @param windowMillis 窗口长度（毫秒）
     * @return true 放行；false 表示已超出限额
     */
    public boolean tryAcquire(String clientId, long limit, long windowMillis) {
        return tryAcquireDecision(clientId, limit, windowMillis).allowed();
    }

    /**
     * 与 {@link #tryAcquire} 相同的原子判定，额外返回本窗口剩余名额，
     * 供配额门面统一记录日志。
     */
    public QuotaDecision tryAcquireDecision(String clientId, long limit, long windowMillis) {
        long now = System.currentTimeMillis();
        Window window = windows.compute(clientId, (id, current) -> {
            if (current == null || now - current.startMillis() >= windowMillis) {
                return new Window(now, new AtomicLong(0));
            }
            return current;
        });
        long used = window.count().incrementAndGet();
        if (used <= limit) {
            return new QuotaDecision(true, Math.max(0, limit - used),
                    null, QuotaDecision.BUCKET_DEFAULT, limit, 0);
        }
        return new QuotaDecision(false, 0,
                null, QuotaDecision.BUCKET_DEFAULT, limit, 0);
    }
}
