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
| `rateLimit` | 默认稳态速率：每个统计窗口稳定允许的请求数，未单独配置配额的范围沿用它 |
| `burstLimit` | 默认突发上限：短时间最多可一次性冲过的请求数；不配置时等于 `rateLimit`（无额外突发余量） |
| `scopeQuotas[n]` | 按接口范围单独配置的 `scope/rateLimit/burstLimit`；各范围独立计数、互不挤占，缺省范围回落到默认配额 |

一次请求要通过以下全部判定（顺序固定，每一步拒绝原因可区分）：

1. **凭据完整性**：四个鉴权头必须齐全，否则 `AUTH_MISSING_CREDENTIALS`；
2. **客户端识别**：`clientId` 必须已注册，否则 `AUTH_UNKNOWN_CLIENT`；
3. **时间戳窗口**：`|服务端时间 - X-Timestamp| ≤ skew`（默认 ±300 秒），超出 `AUTH_TIMESTAMP_EXPIRED`。秒级偏差天然被容忍，不会误伤正常请求；
4. **签名验证**：服务端按同一规范串重算 HMAC-SHA256 并恒定时间比较，不一致 `AUTH_INVALID_SIGNATURE`；
5. **重放检测**：同一 `clientId + nonce` 在 TTL 窗口（默认 600 秒）内只能成功使用一次，重复提交 `AUTH_REPLAY_DETECTED`；
6. **范围控制**：接口上的 `@RequireScope` 必须包含在客户端的 `scopes` 中，否则 `ACCESS_DENIED`；
7. **配额（令牌桶）**：按「客户端 × 本次接口范围」维度判定，超额 `RATE_LIMITED`；
8. **数据归属控制**：业务层从 `ClientContext`（ThreadLocal，请求结束即清理）取 `owner`，所有数据查询强制带 owner 过滤。即使知道他人资源 ID，也查不到数据，也无法在列表中看到他人数据。

> **配额在验签与范围校验通过之后才计数**：任何未通过身份/签名/时间戳/重放/范围校验的请求
> 都会在占用名额之前被拒绝。因此攻击者即便知道一个真实 `clientId` 并伪造大量请求，
> 也无法消耗该客户端真正可用的额度，更不会被算到别的客户端头上——配额桶的键固定为
> 服务端确认过的 `clientId` 与接口 `scope`。

### 配额模型（令牌桶：稳态速率 + 突发余量）

每个 `(clientId, scope)` 拥有一个相互独立的令牌桶：

- **稳态额度（`rateLimit`）**：每 `rate-window-seconds`（默认 60 秒）匀速补充 `rateLimit`
  个令牌。持续压测时吞吐稳定收敛到该速率；突发流量过去后自动平滑收回，不会出现
  "长时间一个不放、然后一次性放开一大片"的抖动；
- **突发余量（`burstLimit`）**：桶容量即突发上限，桶初始为满。客户端短时间冲一波，
  只要不超过 `burstLimit` 就整波放行；令牌用尽后新请求立即 429，随后按稳态速率逐枚补充；
- **分范围独立**：某接口范围配置了 `scopeQuotas` 就用该范围自己的桶；没配的范围沿用
  客户端默认 `rateLimit/burstLimit`。不同范围各算各的账，互不挤占；
- **老配置兼容**：只配 `rate-limit` 时，`burstLimit` 自动等于 `rateLimit`，
  且桶初始为满——在"一个窗口内连发"这种原有用法下，仍是前 `rateLimit` 个放行、
  其后 429，行为与旧版固定额度保持一致（唯一语义差异是跨窗口由"硬重置"变为"匀速补充"，
  对正常调用更平滑友好）。

### 并发安全

- 客户端身份只存在 `ThreadLocal` 中，并在 `afterCompletion` 中无条件清理，线程池复用线程也不会身份串号；
- 重放判定使用 `ConcurrentHashMap.compute` 原子完成，相同 nonce 并发提交有且仅有一个请求通过（有专项测试）；
- 配额桶以 `(clientId, scope)` 为键存放在 `ConcurrentHashMap` 中，桶内"补充 → 判定 → 扣减"
  在同一把锁内一次完成；令牌以整数毫令牌（×1000）运算、不使用浮点，因此突发见底时
  并发压到边界（恰好最后一个放行、下一个拒绝）的结果与线程调度无关，重跑严格一致；
- 桶只在请求通过身份与签名校验后创建，`scope` 取自服务端注解，伪造标识无法制造桶，桶总数有界。

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
| `RATE_LIMITED` | 429 | 超出该客户端在该接口范围上的配额（令牌桶见底），按稳态速率稍后重试；响应 message 带具体 scope 与 rate/burst 参数 |
| `PARAM_INVALID` | 400 | 参数错误，或访问了不存在/不属于自己的资源（不区分二者以防存在性泄露） |
| `INTERNAL_ERROR` | 500 | 服务端内部错误，详情只记录在服务端日志 |

## 4. 配置项

`src/main/resources/application.properties`（均可用同名环境变量覆盖）：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `app.auth.timestamp-skew-seconds` | `300` | 允许的时钟偏差（秒），双向 |
| `app.auth.nonce-ttl-seconds` | `600` | nonce 保留时长，建议 ≥ skew 的两倍窗口 |
| `app.auth.rate-window-seconds` | `60` | 配额稳态窗口长度（秒）：令牌桶每窗口匀速补充 `rateLimit` 个令牌 |
| `app.auth.clients.<id>.secret` | - | Base64 HMAC 密钥（必填） |
| `app.auth.clients.<id>.owner` | - | 数据归属标识（必填） |
| `app.auth.clients.<id>.scopes[n]` | 空 | 授予的接口范围列表 |
| `app.auth.clients.<id>.rate-limit` | `100` | 默认稳态速率：每窗口稳定请求数，未单独配置的范围沿用 |
| `app.auth.clients.<id>.burst-limit` | 等于 `rate-limit` | 默认突发上限（桶容量）；留空则与稳态速率相同，等价于无额外突发余量 |
| `app.auth.clients.<id>.scope-quotas[n].scope` | - | 单独配额对应的接口范围，如 `orders:read` |
| `app.auth.clients.<id>.scope-quotas[n].rate-limit` | - | 该范围的稳态速率（每窗口补充数） |
| `app.auth.clients.<id>.scope-quotas[n].burst-limit` | 等于该范围 `rate-limit` | 该范围的突发上限 |

### 4.1 分范围配额配置示例

某客户端默认额度 100；把"贵"的导出接口单独压到稳态 5、突发 8；读接口压到稳态/突发 3。
其余没列出来的范围继续走默认 100：

```properties
# 默认配额（对所有未单独配置的范围生效）
app.auth.clients.client-x.rate-limit=100
# burst-limit 不配时默认等于 rate-limit，老配置无需任何改动

# 只读接口：稳态 3、突发 3（无额外余量）
app.auth.clients.client-x.scope-quotas[0].scope=orders:read
app.auth.clients.client-x.scope-quotas[0].rate-limit=3
app.auth.clients.client-x.scope-quotas[0].burst-limit=3

# 导出接口（更贵）：稳态 5/窗口，但允许冲到 8
app.auth.clients.client-x.scope-quotas[1].scope=orders:export
app.auth.clients.client-x.scope-quotas[1].rate-limit=5
app.auth.clients.client-x.scope-quotas[1].burst-limit=8
```

**与老配置的兼容性**：

- 只写 `rate-limit` 完全照旧可用：`burst-limit` 缺省取 `rate-limit`，不配 `scope-quotas`
  时所有接口共用客户端默认桶；
- 稳态窗口 `rate-window-seconds` 语义复用为令牌桶的补充周期，无需新增时间配置。

内置示例客户端：

| clientId | owner | scopes | 默认稳态/突发 | 分范围配额 | 用途 |
| --- | --- | --- | --- | --- | --- |
| `client-a` | `tenant-a` | `orders:read` | 1000 / 1000 | 无 | 正常客户端 A |
| `client-b` | `tenant-b` | `orders:read` | 1000 / 1000 | 无 | 正常客户端 B |
| `client-limited` | `tenant-a` | `orders:read` | **3 / 3** | 无 | 配额临界值验证（老用例） |
| `client-noread` | `tenant-a` | 无 | 1000 / 1000 | 无 | scope 越权验证 |
| `client-multiscope` | `tenant-a` | `orders:read`、`orders:export` | 100 / 100 | read **3/3**、export **5/8** | 分范围独立、跨范围不串 |
| `client-burst` | `tenant-a` | `orders:read` | **2 / 5** | 无 | 突发整波放行与边界并发 |

> 生产环境请通过环境变量/配置中心下发密钥，并更换示例密钥。

## 5. 本地验证

### 5.1 自动化测试（推荐，结果稳定可复现）

```bash
mvn test
```

覆盖场景（34 个用例）：

- 验签成功 / 缺鉴权头 / 未知客户端 / 签名错误 / 签名与 body 不匹配；
- 时间戳超窗拒绝、±3 秒时钟偏差放行；
- 相同 nonce 重放拒绝、不同客户端共用 nonce 不判重放；
- scope 不足拒绝、按 ID 越权查他人数据、列表数据不泄露；
- 配额临界值（前 3 个放行、第 4 个 429）、配额按客户端隔离；
- 两个客户端 48 个并发请求交叉不串号；相同 nonce 16 并发仅 1 个通过；
- **令牌桶单元测试（可控时钟，结果确定可复现）**：突发容量整波放行与见底即拒、
  按稳态速率平滑回收（不成片放开）、空闲再久也封顶在突发容量、
  同毫秒并发压界恰好放满容量（连跑多轮结果一致）、不同客户端/不同范围/组合键不串桶、
  rate=0 永不放行；
- **分范围独立**：同一客户端 read 见底不影响 export，二者各按各的容量计数；
- **跨范围并发不串**：两范围 64 个并发交叉，read 恰好成 3、export 恰好成 8；
- **无效请求不计费**：伪造签名 / 未知 clientId / 缺头 / 过期时间戳乱打一批，
  真实客户端的额度一个都不少；scope 越权请求也不占额度。

每个请求在日志中都能看到归属的**客户端与接口范围**，便于按维度追溯：

- 通过：`access granted clientId=... scope=orders:read requestId=... owner=...`；
- 拒绝：`access rejected clientId=... scope=... code=... reason=...`；
- 配额见底：`quota exhausted clientId=... scope=... rate=... burst=... window=...s`。

可在 `target/surefire-reports/` 或控制台中按 `requestId`/`clientId`/`scope` 追溯。

### 5.2 手工冒烟

```bash
# 一键脚本：启动服务 → 成功请求/错误签名/重放/越权/限流 → 关闭服务
scripts/local-verify.sh
```

或手动启动后参考第 2.3 节用 curl 调用。
