package com.github.feng111627.multitenantapiauthjava.demo;

import com.github.feng111627.multitenantapiauthjava.auth.model.ApiException;
import com.github.feng111627.multitenantapiauthjava.auth.model.ErrorCode;
import com.github.feng111627.multitenantapiauthjava.auth.model.RequireScope;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
     * 更"贵"的导出接口，使用独立的接口范围 {@code orders:export}，
     * 可单独配置配额，与 read 范围互不挤占。
     */
    @RequireScope("orders:export")
    @PostMapping("/export")
    public Object export() {
        return orderService.exportMine();
    }
}
