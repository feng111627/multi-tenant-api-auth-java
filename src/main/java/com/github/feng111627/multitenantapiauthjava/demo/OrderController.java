package com.github.feng111627.multitenantapiauthjava.demo;

import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.auth.model.RequireScope;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 对外的订单接口（需要鉴权）。
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService orderService;

    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    @RequireScope("orders:read")
    @PostMapping("/get")
    public Order get(@RequestBody OrderQueryRequest request) {
        if (request == null) {
            throw new ApiException(ErrorCode.PARAM_INVALID, "request body is required");
        }
        return orderService.findById(request.orderId())
                .orElseThrow(() -> new ApiException(ErrorCode.PARAM_INVALID,
                        "order not found or not accessible"));
    }

    @RequireScope("orders:read")
    @PostMapping("/list")
    public Object list() {
        return orderService.listMine();
    }

    /**
     * 轻量探活接口，挂在独立 scope {@code orders:ping} 上，
     * 用于演示"同一客户端不同接口范围各算各的配额"。
     */
    @RequireScope("orders:ping")
    @PostMapping("/ping")
    public Map<String, String> ping() {
        return Map.of("status", "pong");
    }
}
