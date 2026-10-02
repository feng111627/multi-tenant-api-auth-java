package com.github.feng111627.multitenantapiauthjava.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 请求标识（nonce）存储：用于重放攻击检测。
 *
 * 同一个 clientId 下相同的 nonce 在 TTL 内只允许出现一次；
 * 过期条目会被惰性清理，避免内存无限增长。
 */
@Component
public class NonceStore {

    private final Map<String, Long> seen = new ConcurrentHashMap<>();

    private final long ttlMillis;
    private final Clock clock;

    @Autowired
    public NonceStore(@Value("${auth.nonce-ttl-millis:300000}") long ttlMillis) {
        this(ttlMillis, Clock.systemUTC());
    }

    NonceStore(long ttlMillis, Clock clock) {
        this.ttlMillis = ttlMillis;
        this.clock = clock;
    }

    /**
     * 尝试记录一个 nonce；若已存在（重复提交）返回 false。
     */
    public boolean markIfAbsent(String clientId, String nonce) {
        if (clientId == null || nonce == null || nonce.isBlank()) {
            return false;
        }
        long now = clock.millis();
        evictExpired(now);
        String key = clientId + ":" + nonce;
        return seen.putIfAbsent(key, now + ttlMillis) == null;
    }

    private void evictExpired(long now) {
        seen.entrySet().removeIf(e -> e.getValue() <= now);
    }
}
