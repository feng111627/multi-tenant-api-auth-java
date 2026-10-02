# 对外接口鉴权与访问控制说明

本文档说明 `/api/**` 对外接口的鉴权模型、签名算法、错误码、配置项与本地验证方式。

## 1. 鉴权模型

每个外部客户端在服务端注册一条凭据：

| 属性 | 含义 |
| --- | --- |
| `clientId` | 客户端唯一标识，随请求头传递 |
| `secret` | HMAC 密钥（Base64 编码），仅客户端与服务端持有，不随请求传输 |
| `scopes` | 允许访问的接口范围，例如 `orders:read` |
| `owner` | 数据归属标识（租户），业务查询强制按它过滤数据 |
| `rateLimit` | 每个统计窗口内允许的最大请求数 |

一次请求要通过以下全部判定（顺序固定，每一步拒绝原因可区分）：

1. **凭据完整性**：四个鉴权头必须齐全，否则 `AUTH_MISSING_CREDENTIALS`；
2. **客户端识别**：`clientId` 必须已注册，否则 `AUTH_UNKNOWN_CLIENT`；
3. **限流**：按客户端维度的固定窗口计数，超额 `RATE_LIMITED`（限流先于验签，被限流请求不会消耗 nonce）；
4. **时间戳窗口**：`|服务端时间 - X-Timestamp| ≤ skew`（默认 ±300 秒），超出 `AUTH_TIMESTAMP_EXPIRED`。秒级偏差天然被容忍，不会误伤正常请求；
5. **签名验证**：服务端按同一规范串重算 HMAC-SHA256 并恒定时间比较，不一致 `AUTH_INVALID_SIGNATURE`；
6. **重放检测**：同一 `clientId + nonce` 在 TTL 窗口（默认 600 秒）内只能成功使用一次，重复提交 `AUTH_REPLAY_DETECTED`；
7. **范围控制**：接口上的 `@RequireScope` 必须包含在客户端的 `scopes` 中，否则 `ACCESS_DENIED`；
8. **数据归属控制**：业务层从 `ClientContext`（ThreadLocal，请求结束即清理）取 `owner`，所有数据查询强制带 owner 过滤。即使知道他人资源 ID，也查不到数据，也无法在列表中看到他人数据。

### 并发安全

- 客户端身份只存在 `ThreadLocal` 中，并在 `afterCompletion` 中无条件清理，线程池复用线程也不会身份串号；
- 重放判定使用 `ConcurrentHashMap.compute` 原子完成，相同 nonce 并发提交有且仅有一个请求通过（有专项测试）；
- 限流计数基于原子计数 + 原子窗口切换，临界值（恰好第 N、N+1 个请求）判定稳定。

## 2. 签名算法

### 2.1 请求头

| 请求头 | 必填 | 说明 |
| --- | --- | --- |
| `X-Client-Id` | 是 | 客户端标识 |
| `X-Timestamp` | 是 | 请求构造时的 Unix **秒**级时间戳 |
| `X-Nonce` | 是 | 请求唯一标识，建议 UUID；同一客户端窗口内不可复用 |
| `X-Signature` | 是 | 对规范串计算的 HMAC-SHA256，Base64 编码 |
| `X-Request-Id` | 否 | 便于链路追踪的请求 ID；不传时日志用 nonce 兜底 |

### 2.2 规范串（canonical request）

```
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(BODY)
```

- `METHOD`：HTTP 方法大写，如 `POST`；
- `PATH`：请求路径（不含 query），如 `/api/orders/get`；
- `BODY`：原始请求体字节的 UTF-8 字符串（空 body 用空串），先做 SHA-256 再小写 HEX；
- `\n` 为换行符（LF）。

### 2.3 计算签名

```
signature = Base64( HMAC_SHA256( key = Base64Decode(secret), msg = canonicalString ) )
```

curl/openssl 示例（示例 key 解码后即字符串 `secret-a-secret-a-secret-`）：

```bash
BODY='{"orderId":"ORD-1001"}'
TS=$(date +%s)
NONCE=$(uuidgen)
BODY_HASH=$(printf '%s' "$BODY" | openssl dgst -sha256 | awk '{print $NF}')
CANON=$(printf 'POST\n/api/orders/get\n%s\n%s\n%s' "$TS" "$NONCE" "$BODY_HASH")
SIG=$(printf '%s' "$CANON" | openssl dgst -sha256 -hmac "secret-a-secret-a-secret-" -binary | base64 -w0)

curl -s http://localhost:8080/api/orders/get \
  -H 'Content-Type: application/json' \
  -H "X-Client-Id: client-a" \
  -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

## 3. 统一错误响应

任何错误（含内部异常）都返回结构稳定的 JSON，不把堆栈/底层异常抛给调用方：

```json
{
  "code": "AUTH_INVALID_SIGNATURE",
  "message": "signature does not match canonical request",
  "requestId": "req-xxxx",
  "timestamp": 1790899575253
}
```

| code | HTTP 状态码 | 含义与客户端处理建议 |
| --- | --- | --- |
| `AUTH_MISSING_CREDENTIALS` | 401 | 鉴权头缺失，检查签名组件是否齐全 |
| `AUTH_UNKNOWN_CLIENT` | 401 | clientId 未注册/已停用 |
| `AUTH_INVALID_SIGNATURE` | 401 | 签名错误：规范串构造、密钥、body 与签名不一致 |
| `AUTH_TIMESTAMP_EXPIRED` | 401 | 时间戳超出 ±skew 窗口：先对时再重试 |
| `AUTH_REPLAY_DETECTED` | 409 | nonce 在窗口内重复使用，请生成新 nonce |
| `ACCESS_DENIED` | 403 | 客户端没有该接口的 scope |
| `RATE_LIMITED` | 429 | 超出客户端配额，下一窗口后重试；响应为标准 JSON |
| `PARAM_INVALID` | 400 | 参数错误，或访问了不存在/不属于自己的资源（不区分二者以防存在性泄露） |
| `INTERNAL_ERROR` | 500 | 服务端内部错误，详情只记录在服务端日志 |

## 4. 配置项

`src/main/resources/application.properties`（均可用同名环境变量覆盖）：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `app.auth.timestamp-skew-seconds` | `300` | 允许的时钟偏差（秒），双向 |
| `app.auth.nonce-ttl-seconds` | `600` | nonce 保留时长，建议 ≥ skew 的两倍窗口 |
| `app.auth.rate-window-seconds` | `60` | 限流固定窗口长度（秒） |
| `app.auth.clients.<id>.secret` | - | Base64 HMAC 密钥（必填） |
| `app.auth.clients.<id>.owner` | - | 数据归属标识（必填） |
| `app.auth.clients.<id>.scopes[n]` | 空 | 授予的接口范围列表 |
| `app.auth.clients.<id>.rate-limit` | `100` | 每窗口最大请求数 |

内置四个示例客户端：

| clientId | owner | scopes | 限额 | 用途 |
| --- | --- | --- | --- | --- |
| `client-a` | `tenant-a` | `orders:read` | 1000 | 正常客户端 A |
| `client-b` | `tenant-b` | `orders:read` | 1000 | 正常客户端 B |
| `client-limited` | `tenant-a` | `orders:read` | **3** | 限流临界值验证 |
| `client-noread` | `tenant-a` | 无 | 1000 | scope 越权验证 |

> 生产环境请通过环境变量/配置中心下发密钥，并更换示例密钥。

## 5. 本地验证

### 5.1 自动化测试（推荐，结果稳定可复现）

```bash
mvn test
```

覆盖场景（19 个用例）：

- 验签成功 / 缺鉴权头 / 未知客户端 / 签名错误 / 签名与 body 不匹配；
- 时间戳超窗拒绝、±3 秒时钟偏差放行；
- 相同 nonce 重放拒绝、不同客户端共用 nonce 不判重放；
- scope 不足拒绝、按 ID 越权查他人数据、列表数据不泄露；
- 限流临界值（前 3 个放行、第 4 个 429）、限流按客户端隔离；
- 两个客户端 48 个并发请求交叉不串号；相同 nonce 16 并发仅 1 个通过。

测试日志对每个请求打印 `requestId`、`clientId`、`nonce` 与判定依据
（`auth accepted ... reason=signature_ok` / `auth rejected ... code=... reason=...`），
可在 `target/surefire-reports/` 或控制台中按 requestId 追溯。

### 5.2 手工冒烟

```bash
# 一键脚本：启动服务 → 成功请求/错误签名/重放/越权/限流 → 关闭服务
scripts/local-verify.sh
```

或手动启动后参考第 2.3 节用 curl 调用。
