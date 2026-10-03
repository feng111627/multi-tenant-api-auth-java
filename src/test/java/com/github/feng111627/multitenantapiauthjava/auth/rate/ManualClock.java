package com.github.feng111627.multitenantapiauthjava.auth.rate;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

/**
 * 测试用可拨动时钟：时间只在测试显式 {@link #advance(long)} 时前进，
 * 让令牌桶的补充/回收行为完全确定、可复现，不依赖墙钟与调度。
 */
class ManualClock extends Clock {

    private long millis;

    ManualClock() {
        this(1_000_000L);
    }

    ManualClock(long startMillis) {
        this.millis = startMillis;
    }

    void advance(long deltaMillis) {
        this.millis += deltaMillis;
    }

    @Override
    public long millis() {
        return millis;
    }

    @Override
    public ZoneId getZone() {
        return ZoneId.of("UTC");
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return Instant.ofEpochMilli(millis);
    }
}
