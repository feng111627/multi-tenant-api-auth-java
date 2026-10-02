package com.github.feng111627.multitenantapiauthjava.auth.sign;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 已消费请求标识（nonce）缓存，用于重放检测。
 *
 * <p>键为 {@code clientId + ":" + nonce}，值为过期时间戳。
 * 使用 {@link ConcurrentHashMap#compute} 做原子的"不存在或已过期则占用"操作，
 * 保证并发的相同请求只有一个能通过。过期项惰性清理。</p>
 */
@Component
public class ReplayCache {

    private final Map<String, Long> seen = new ConcurrentHashMap<>();

    /**
     * 尝试占用一个 nonce。
     *
     * @return true 表示首次出现（允许通过）；false 表示 TTL 窗口内重复提交
     */
    public boolean registerIfAbsent(String clientId, String nonce, long ttlMillis) {
        long now = System.currentTimeMillis();
        long expireAt = now + ttlMillis;
        String key = clientId + ":" + nonce;
        boolean[] accepted = {false};
        seen.compute(key, (k, oldExpireAt) -> {
            if (oldExpireAt == null || oldExpireAt <= now) {
                accepted[0] = true;
                return expireAt;
            }
            accepted[0] = false;
            return oldExpireAt;
        });
        if (seen.size() > 10_000) {
            evictExpired(now);
        }
        return accepted[0];
    }

    private void evictExpired(long now) {
        seen.entrySet().removeIf(e -> e.getValue() <= now);
    }
}
