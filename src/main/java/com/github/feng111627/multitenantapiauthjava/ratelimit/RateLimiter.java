package com.github.feng111627.multitenantapiauthjava.ratelimit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按客户端维度的请求频率限制（令牌桶算法）。
 *
 * 每个 clientId 一个独立的桶：默认容量 capacity，按 refillPerSecond 匀速补充；
 * 可通过 capacityOverrides（格式 "client-a:3,client-b:100"）为单个客户端指定容量；
 * 取不到令牌时请求被拒绝（HTTP 429）。
 */
@Component
public class RateLimiter {

    private final int capacity;
    private final double refillPerSecond;
    private final Map<String, Integer> capacityOverrides;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(@Value("${ratelimit.capacity:10}") int capacity,
                       @Value("${ratelimit.refill-per-second:5}") double refillPerSecond,
                       @Value("${ratelimit.capacity-overrides:}") String capacityOverrides) {
        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
        this.capacityOverrides = parseOverrides(capacityOverrides);
    }

    private static Map<String, Integer> parseOverrides(String overrides) {
        Map<String, Integer> result = new HashMap<>();
        if (overrides == null || overrides.isBlank()) {
            return result;
        }
        for (String entry : overrides.split(",")) {
            String[] kv = entry.trim().split(":");
            if (kv.length == 2) {
                result.put(kv[0].trim(), Integer.parseInt(kv[1].trim()));
            }
        }
        return result;
    }

    /**
     * 尝试为指定客户端获取一个令牌。
     */
    public boolean tryAcquire(String clientId) {
        Bucket bucket = buckets.computeIfAbsent(clientId,
                k -> new Bucket(capacityOverrides.getOrDefault(k, capacity)));
        return bucket.tryAcquire();
    }

    /**
     * 当前剩余令牌数（主要用于测试与观测）。
     */
    public double availableTokens(String clientId) {
        Bucket bucket = buckets.get(clientId);
        return bucket == null ? capacityOverrides.getOrDefault(clientId, capacity) : bucket.available();
    }

    private final class Bucket {
        private final int bucketCapacity;
        private double tokens;
        private long lastRefillNanos;

        Bucket(int bucketCapacity) {
            this.bucketCapacity = bucketCapacity;
            this.tokens = bucketCapacity;
            this.lastRefillNanos = System.nanoTime();
        }

        synchronized boolean tryAcquire() {
            refill();
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }

        synchronized double available() {
            refill();
            return tokens;
        }

        private void refill() {
            long now = System.nanoTime();
            double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
            if (elapsedSeconds > 0) {
                tokens = Math.min(bucketCapacity, tokens + elapsedSeconds * refillPerSecond);
                lastRefillNanos = now;
            }
        }
    }
}
