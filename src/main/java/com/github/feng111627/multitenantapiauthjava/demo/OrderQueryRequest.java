package com.github.feng111627.multitenantapiauthjava.demo;

/**
 * 订单查询请求体。
 */
public record OrderQueryRequest(
        String orderId
) {
}
