package com.github.feng111627.multitenantapiauthjava.demo;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 示例业务服务：订单按租户归属存储，读写都必须显式带上租户标识，
 * 从数据层保证不会把其他租户的数据返回给当前客户端。
 */
@Service
public class OrderService {

    public record Order(String id, String tenantId, String item, long amount) {
    }

    private final Map<String, List<Order>> ordersByTenant = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(0);

    public OrderService() {
        // 预置演示数据：两个租户各自有订单
        save("tenant-a", new Order("a-1", "tenant-a", "keyboard", 2));
        save("tenant-a", new Order("a-2", "tenant-a", "mouse", 5));
        save("tenant-b", new Order("b-1", "tenant-b", "monitor", 1));
    }

    public List<Order> listByTenant(String tenantId) {
        return List.copyOf(ordersByTenant.getOrDefault(tenantId, List.of()));
    }

    /**
     * 按订单 id 查询，仅当订单属于指定租户时才返回，否则 empty（不泄露其他租户数据）。
     */
    public Optional<Order> findByIdForTenant(String tenantId, String orderId) {
        return ordersByTenant.getOrDefault(tenantId, List.of()).stream()
                .filter(o -> o.id().equals(orderId))
                .findFirst();
    }

    public Order create(String tenantId, String item, long amount) {
        Order order = new Order(tenantId + "-" + sequence.incrementAndGet() + "-" + System.nanoTime() % 1000,
                tenantId, item, amount);
        save(tenantId, order);
        return order;
    }

    private void save(String tenantId, Order order) {
        ordersByTenant.computeIfAbsent(tenantId, k -> new CopyOnWriteArrayList<>()).add(order);
    }
}
