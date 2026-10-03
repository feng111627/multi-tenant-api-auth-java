package com.github.feng111627.multitenantapiauthjava.auth.rate;

/**
 * 一次配额判定结果。
 *
 * @param allowed    是否放行
 * @param remaining  判定后剩余的整名额（固定窗口为本窗口剩余；令牌桶为桶内剩余整令牌）
 * @param scope      本次记账归属的接口范围；null 表示无 @RequireScope 的默认桶
 * @param bucketType 命中的桶类型：{@code default}（默认固定窗口）或 {@code scope}（分范围令牌桶）
 * @param rateLimit  生效的稳态额度
 * @param burst      生效的突发余量（默认桶恒为 0）
 */
public record QuotaDecision(
        boolean allowed,
        long remaining,
        String scope,
        String bucketType,
        long rateLimit,
        long burst
) {

    public static final String BUCKET_DEFAULT = "default";
    public static final String BUCKET_SCOPE = "scope";

    /** 记账归属名，用于日志：无 scope 时显示 default。 */
    public String scopeLabel() {
        return scope == null ? BUCKET_DEFAULT : scope;
    }
}
