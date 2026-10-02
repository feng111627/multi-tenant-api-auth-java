package com.github.feng111627.multitenantapiauthjava.demo;

/**
 * 演示用订单数据。
 */
public record Order(
        String orderId,
        String ownerId,
        String subject,
        long amount
) {
}
