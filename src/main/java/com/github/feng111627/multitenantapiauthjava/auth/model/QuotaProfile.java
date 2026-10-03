package com.github.feng111627.multitenantapiauthjava.auth.model;

/**
 * 单个配额维度（客户端默认或某个接口范围）的配额画像。
 *
 * @param rateLimit  稳态速率：每个统计窗口稳定放行的请求数，同时也是令牌桶的补充速率
 * @param burstLimit 突发上限：令牌桶容量，短时间内最多允许一次性冲过的请求数；
 *                   未单独配置时与 {@link #rateLimit} 相同（无额外突发余量）
 */
public record QuotaProfile(long rateLimit, long burstLimit) {
}
