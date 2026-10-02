# 接口鉴权与访问控制说明

## 1. 鉴权模型

外部客户端调用 `/api/**` 接口前，需使用事先分配的密钥对请求做 HMAC-SHA256 签名。

### 请求头

| 请求头 | 说明 |
|---|---|
| `X-Client-Id` | 客户端标识（服务端已注册） |
| `X-Timestamp` | 客户端当前时间戳（毫秒） |
| `X-Nonce` | 本次请求唯一标识，TTL 内不得重复 |
| `X-Signature` | 签名值（hex 编码） |

### 待签名串与签名算法

```
canonical = METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" SHA256_HEX(BODY)
signature = HEX( HMAC-SHA256(secret, canonical) )
```

- `METHOD` 大写；`PATH` 为请求路径（不含 query）；`BODY` 为原始请求体（无 body 时按空串）。
- 服务端用同样规则重算签名，并以常量时间比较，防止时序侧信道。

### 服务端检查顺序（任一失败即拒绝，错误码可区分）

1. 客户端是否已注册 → `CLIENT_UNKNOWN`
2. 时间戳偏差是否在容忍窗口内（默认 ±300s，秒级时钟偏差可容忍） → `TIMESTAMP_EXPIRED`
3. 签名是否匹配 → `SIGNATURE_INVALID`
4. nonce 是否在 TTL 内重复 → `NONCE_REPLAYED`
5. 是否超出该客户端限流额度 → `RATE_LIMITED`
6. 路径是否在该客户端允许列表内（Ant 风格通配符） → `SCOPE_FORBIDDEN`

全部通过后，客户端身份写入基于 `ThreadLocal` 的 `ClientContext`（线程隔离，并发请求不会串号），
业务层按该身份的 `tenantId` 存取数据；访问不属于本租户的数据返回 `TENANT_FORBIDDEN`，
且不透露数据是否存在。请求结束统一清理上下文。

## 2. 错误码

统一错误返回体：`{"code": "...", "message": "...", "requestId": "clientId:nonce"}`

| code | HTTP | 含义 |
|---|---|---|
| `CLIENT_UNKNOWN` | 401 | 客户端未注册或缺少身份头 |
| `TIMESTAMP_EXPIRED` | 401 | 时间戳缺失、格式错误或超出容忍窗口 |
| `SIGNATURE_INVALID` | 401 | 签名校验失败 |
| `NONCE_REPLAYED` | 401 | 同一 nonce 在 TTL 内重复提交 |
| `RATE_LIMITED` | 429 | 超出该客户端请求频率限额 |
| `SCOPE_FORBIDDEN` | 403 | 路径不在客户端允许范围内 |
| `TENANT_FORBIDDEN` | 403 | 数据不属于当前客户端的租户 |
| `BAD_REQUEST` | 400 | 参数缺失/格式错误 |
| `INTERNAL_ERROR` | 500 | 内部异常（不泄露底层细节） |

## 3. 配置项

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `auth.timestamp-tolerance-millis` | 300000 | 时间戳容忍窗口，需大于客户端与服务端的时钟偏差 |
| `auth.nonce-ttl-millis` | 300000 | nonce 有效期，建议与时间戳窗口一致 |
| `ratelimit.capacity` | 10 | 每客户端令牌桶默认容量 |
| `ratelimit.refill-per-second` | 5 | 令牌每秒补充速率 |
| `ratelimit.capacity-overrides` | 空 | 单客户端容量覆盖，格式 `client-a:3,client-b:100` |
| `auth.clients[n].client-id` | — | 客户端标识 |
| `auth.clients[n].secret` | — | 签名密钥（生产环境应外置到密钥管理） |
| `auth.clients[n].tenant-id` | — | 数据归属租户 |
| `auth.clients[n].allowed-paths` | — | 允许访问的路径，支持 Ant 通配符，如 `/api/orders/**` |

## 4. 本地验证

### 运行测试（覆盖验签失败、重放、越权、限流临界值、并发）

```bash
mvn test
```

测试日志会打印每个请求的 `requestId`（`clientId:nonce`）与判定依据。

### 手工验证（签名请求示例）

```bash
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080

TS=$(date +%s%3N); NONCE=$(uuidgen)
BODY=""
CANONICAL=$(printf 'GET\n/api/orders\n%s\n%s\n%s' "$TS" "$NONCE" "$(printf '%s' "$BODY" | sha256sum | cut -d' ' -f1)")
SIG=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "secret-for-client-a" | cut -d' ' -f2)

curl -s localhost:8080/api/orders \
  -H "X-Client-Id: client-a" -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" -H "X-Signature: $SIG"
```

- 改错 `secret` 重签 → `SIGNATURE_INVALID`
- 同一 `nonce` 再发一次 → `NONCE_REPLAYED`
- 把 `TS` 改成 1 小时前并重签 → `TIMESTAMP_EXPIRED`
- 用 `client-b` 请求 `/api/orders/b-1` → `SCOPE_FORBIDDEN`
- 用 `client-a` 请求 `/api/orders/b-1`（tenant-b 的数据） → `TENANT_FORBIDDEN`
