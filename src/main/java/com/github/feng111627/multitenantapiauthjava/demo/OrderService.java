package com.github.feng111627.multitenantapiauthjava.demo;

import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientContext;
import com.github.feng111627.multitenantapiauthjava.auth.model.ClientCredentials;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * 按 ownerId 隔离的订单服务，演示"能操作的数据归属"控制：
 * 数据归属在服务层依据 {@link ClientContext} 强制过滤，
 * 即使知道别人的 orderId 也拿不到数据（不会存在性泄露）。
 */
@Service
public class OrderService {

    private static final List<Order> STORE = List.of(
            new Order("ORD-1001", "tenant-a", "A 公司一月账单", 10000),
            new Order("ORD-1002", "tenant-a", "A 公司二月账单", 20000),
            new Order("ORD-2001", "tenant-b", "B 公司一月账单", 30000),
            new Order("ORD-2002", "tenant-b", "B 公司二月账单", 40000)
    );

    /**
     * 查询单个订单。不属于当前客户端的数据一律按"参数错误"处理，
     * 不返回 404 之外的存在性暗示，也不返回数据本体。
     */
    public Optional<Order> findById(String orderId) {
        ClientCredentials client = requireClient();
        if (orderId == null || orderId.isBlank()) {
            throw new ApiException(ErrorCode.PARAM_INVALID, "orderId must not be blank");
        }
        return STORE.stream()
                .filter(order -> order.orderId().equals(orderId))
                .filter(order -> order.ownerId().equals(client.ownerId()))
                .findFirst();
    }

    /**
     * 列出当前客户端归属下的全部订单，查询条件中无法注入他人的 ownerId。
     */
    public List<Order> listMine() {
        ClientCredentials client = requireClient();
        return STORE.stream()
                .filter(order -> order.ownerId().equals(client.ownerId()))
                .toList();
    }

    /**
     * 导出当前客户端归属下的全部订单（演示另一个更"贵"的接口范围
     * {@code orders:export}，配额独立于 {@code orders:read}）。
     */
    public List<Order> exportMine() {
        ClientCredentials client = requireClient();
        return STORE.stream()
                .filter(order -> order.ownerId().equals(client.ownerId()))
                .toList();
    }

    private static ClientCredentials requireClient() {
        ClientCredentials client = ClientContext.get();
        if (client == null) {
            throw new ApiException(ErrorCode.INTERNAL_ERROR, "client context not initialized");
        }
        return client;
    }
}
