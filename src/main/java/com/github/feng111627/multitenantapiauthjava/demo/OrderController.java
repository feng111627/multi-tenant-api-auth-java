package com.github.feng111627.multitenantapiauthjava.demo;

import com.github.feng111627.multitenantapiauthjava.auth.ClientContext;
import com.github.feng111627.multitenantapiauthjava.error.ApiException;
import com.github.feng111627.multitenantapiauthjava.error.ErrorCode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 示例业务接口：订单数据按当前客户端的租户归属隔离。
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService orderService;

    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    @GetMapping
    public List<OrderService.Order> list() {
        return orderService.listByTenant(currentTenant());
    }

    @GetMapping("/{id}")
    public OrderService.Order get(@PathVariable String id) {
        // 订单不属于当前租户时按越权拒绝，且不透露订单是否存在
        return orderService.findByIdForTenant(currentTenant(), id)
                .orElseThrow(() -> new ApiException(ErrorCode.TENANT_FORBIDDEN, 403,
                        "order not accessible for current tenant"));
    }

    @PostMapping
    public OrderService.Order create(@RequestBody Map<String, Object> body) {
        Object item = body.get("item");
        Object amount = body.get("amount");
        if (item == null || amount == null) {
            throw new IllegalArgumentException("item and amount are required");
        }
        return orderService.create(currentTenant(), item.toString(), ((Number) amount).longValue());
    }

    private String currentTenant() {
        String tenantId = ClientContext.currentTenantId();
        if (tenantId == null) {
            throw new ApiException(ErrorCode.CLIENT_UNKNOWN, 401, "no authenticated client in context");
        }
        return tenantId;
    }
}
