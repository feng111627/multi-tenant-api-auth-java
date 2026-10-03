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
| `rateLimit` | 默认配额：每个统计窗口内允许的最大请求数（未单独配置的 scope 沿用） |
| `scopeQuotas` | 可选；按 scope 单独配置的稳态额度 `rateLimit` 与突发余量 `burst`，详见 1.1 |

一次请求要通过以下全部判定（顺序固定，每一步拒绝原因可区分）：

1. **凭据完整性**：四个鉴权头必须齐全，否则 `AUTH_MISSING_CREDENTIALS`；
2. **客户端识别**：`clientId` 必须已注册，否则 `AUTH_UNKNOWN_CLIENT`；
3. **时间戳窗口**：`|服务端时间 - X-Timestamp| ≤ skew`（默认 ±300 秒），超出 `AUTH_TIMESTAMP_EXPIRED`。秒级偏差天然被容忍，不会误伤正常请求；
4. **签名验证**：服务端按同一规范串重算 HMAC-SHA256 并恒定时间比较，不一致 `AUTH_INVALID_SIGNATURE`；
5. **重放检测**：同一 `clientId + nonce` 在 TTL 窗口（默认 600 秒）内只能成功使用一次，重复提交 `AUTH_REPLAY_DETECTED`；
6. **范围控制**：接口上的 `@RequireScope` 必须包含在客户端的 `scopes` 中，否则 `ACCESS_DENIED`；
7. **配额占用**：只有上面全部通过的请求才记账，按"客户端 + 接口范围"判定（见第 1.1 节），超额 `RATE_LIMITED`；
8. **数据归属控制**：业务层从 `ClientContext`（ThreadLocal，请求结束即清理）取 `owner`，所有数据查询强制带 owner 过滤。即使知道他人资源 ID，也查不到数据，也无法在列表中看到他人数据。

> 顺序说明：配额判定位于验签与 scope 校验**之后**。因此攻击者即使知道某个客户端标识，伪造签名、缺头、重放、越权的请求都会先被拒绝，**不会占用该客户端的任何配额，也不会被算到别的客户端身上**。

### 1.1 分范围配额（新）

配额可以按接口范围（scope）拆开配置，同一客户端在不同范围上各算各的账，互不挤占：

- **默认额度**：客户端级 `rate-limit`，沿用原有固定窗口算法（每窗口 N 个，窗口结束整窗重置）。没有 `@RequireScope` 的接口、以及没有单独配置的 scope，都记在这本默认账上；
- **分范围额度**：对某个 scope 显式配置后，该 scope 的请求改记到独立的**令牌桶**上，与默认账、与其它 scope 完全隔离；
- **稳态 + 突发**：每个分范围桶有两个参数：
  - `rate-limit`：稳态额度，每 `rate-window-seconds`（默认 60 秒）平滑补充 N 个令牌；
  - `burst`：在稳态额度之上额外预留的突发余量。桶容量 = `rate-limit + burst`，桶初始为满。
    客户端短时间冲一波，只要不超过桶容量就整波放行；令牌随时间**平滑回收**，波次过去后自动回到稳态速率，不会出现"长时间不放行、窗口切换时一次性放开一大片"的抖动。
  - `burst` 缺省为 `0`，此时桶容量恰为 `rate-limit`；
- **未配置即兼容**：`scope-quotas` 整块或某个 scope 不配置时，行为与旧版本完全一致（固定窗口、客户端单一总额度）。

配额判定的确定性：

- 令牌数以整数放大 10^6 倍保存、全程整数运算，无浮点误差；同一桶的"按时间补充 + 扣减"在同一把锁内原子完成，并发压到边界时恰好"最后一个放行、下一个拒绝"，重跑结果一致；
- 桶按 `(clientId, scope)` 分键、各持一把锁，并发下不同范围的计数不会互相串；
- 每次判定都在日志中记录归属，例如
  `access granted clientId=client-scoped-2 scope=orders:read bucket=scope remaining=3`，
  超额时
  `access rejected ... scope=orders:ping code=RATE_LIMITED reason=rate limit exceeded for scope 'orders:ping' (bucket=scope, rate=5, burst=0)`。
  未单独配置的范围显示 `bucket=default`。

### 并发安全

- 客户端身份只存在 `ThreadLocal` 中，并在 `afterCompletion` 中无条件清理，线程池复用线程也不会身份串号；
- 重放判定使用 `ConcurrentHashMap.compute` 原子完成，相同 nonce 并发提交有且仅有一个请求通过（有专项测试）；
- 默认固定窗口基于原子计数 + 原子窗口切换，临界值（恰好第 N、N+1 个请求）判定稳定；
- 分范围令牌桶按 `(clientId, scope)` 分桶分锁，"补充 + 扣减"在桶内串行完成，32 并发冲容量为 3 的桶时恰好 3 个放行、其余 429；两个 scope 各 32 并发交叉时各自恰好放过 3 个，计数互不串。

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
| `RATE_LIMITED` | 429 | 超出该客户端在该接口范围上的配额（默认桶或分范围令牌桶），稳态速率下稍后重试；响应为标准 JSON，message 含 scope 与桶类型 |
| `PARAM_INVALID` | 400 | 参数错误，或访问了不存在/不属于自己的资源（不区分二者以防存在性泄露） |
| `INTERNAL_ERROR` | 500 | 服务端内部错误，详情只记录在服务端日志 |

## 4. 配置项

`src/main/resources/application.properties`（均可用同名环境变量覆盖）：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `app.auth.timestamp-skew-seconds` | `300` | 允许的时钟偏差（秒），双向 |
| `app.auth.nonce-ttl-seconds` | `600` | nonce 保留时长，建议 ≥ skew 的两倍窗口 |
| `app.auth.rate-window-seconds` | `60` | 默认固定窗口长度（秒）；同时是分范围令牌桶的稳态补充周期 |
| `app.auth.clients.<id>.secret` | - | Base64 HMAC 密钥（必填） |
| `app.auth.clients.<id>.owner` | - | 数据归属标识（必填） |
| `app.auth.clients.<id>.scopes[n]` | 空 | 授予的接口范围列表 |
| `app.auth.clients.<id>.rate-limit` | `100` | 默认稳态/窗口配额；未单独配置的 scope 沿用它 |
| `app.auth.clients.<id>.scope-quotas.<scope>.rate-limit` | 继承客户端 `rate-limit` | 该 scope 的独立稳态配额（令牌桶每窗口补充量） |
| `app.auth.clients.<id>.scope-quotas.<scope>.burst` | `0` | 该 scope 在稳态额度之上的额外突发余量 |

#### 配置示例（YAML）

> scope 名通常含冒号（如 `orders:read`），在 `.properties` 扁平化 key 中冒号会被当作分隔符，
> 且 Spring 松散绑定会把 map key 中的 `:`、`-` 剥掉（服务端查找时做同样的归一化，因此
> `orders:read` 这样配置即可正确匹配）。为可读性，分范围配额建议写在 `application.yml`：

```yaml
app:
  auth:
    clients:
      client-scoped:
        secret: c2VjcmV0...
        owner: tenant-a
        scopes:
          - orders:read
          - orders:ping
        rate-limit: 1000              # 默认额度（未单独配的 scope 走它，固定窗口）
        scope-quotas:
          "orders:read":
            rate-limit: 2             # 稳态：每 60s 补 2 个
            burst: 2                  # 突发：可短时一波冲到 4 个，之后平滑回到 2/60s
          "orders:ping":
            rate-limit: 5             # 稳态 5，无突发（burst 可省略，默认 0）
```

兼容性规则：

- 不写 `scope-quotas`：所有请求记在客户端默认固定窗口上，与旧版本逐字节一致；
- 只配部分 scope：配了的走令牌桶，没配的（含无 `@RequireScope` 的接口）走默认窗口；
- `scope-quotas.<scope>.rate-limit` 省略或 ≤0 时继承客户端默认 `rate-limit`，只单独放大 `burst` 也合法。

内置示例客户端（原有四个 + 配额演示若干，后者定义在 `application.yml`）：

| clientId | owner | scopes | 配额 | 用途 |
| --- | --- | --- | --- | --- |
| `client-a` | `tenant-a` | `orders:read` | 默认 1000 | 正常客户端 A |
| `client-b` | `tenant-b` | `orders:read` | 默认 1000 | 正常客户端 B |
| `client-limited` | `tenant-a` | `orders:read` | 默认 **3** | 旧固定窗口临界值验证 |
| `client-noread` | `tenant-a` | 无 | 默认 1000 | scope 越权验证 |
| `client-scoped` 系列 | `tenant-a` | `orders:read`/`orders:ping` | read 稳态 2+突发 2，ping 稳态 5 | 分范围独立、突发、默认沿用验证 |
| `client-default` | `tenant-a` | `orders:ping` | 默认 2（ping 未单配） | 未配置范围沿用默认验证 |
| `client-edge` 系列 | `tenant-a` | `orders:ping`（edge-3 含 read） | 稳态 3，突发 0 | 并发达界、跨范围不串、防刷验证 |

> 生产环境请通过环境变量/配置中心下发密钥，并更换示例密钥。

## 5. 本地验证

### 5.1 自动化测试（推荐，结果稳定可复现）

```bash
mvn test
```

覆盖场景（32 个用例）：

- 验签成功 / 缺鉴权头 / 未知客户端 / 签名错误 / 签名与 body 不匹配；
- 时间戳超窗拒绝、±3 秒时钟偏差放行；
- 相同 nonce 重放拒绝、不同客户端共用 nonce 不判重放；
- scope 不足拒绝、按 ID 越权查他人数据、列表数据不泄露；
- 默认固定窗口临界值（前 3 个放行、第 4 个 429）、限流按客户端隔离；
- 两个客户端 48 个并发请求交叉不串号；相同 nonce 16 并发仅 1 个通过；
- **分范围配额**：两个 scope 配额独立、打空一个不影响另一个；未配置的 scope 沿用客户端默认额度（`bucket=default`）；
- **突发与回收**：稳态 2+突发 2 的桶短时整波放行 4 个、第 5 个见底拒绝；可控时钟单测验证令牌平滑回收（半窗口补 1 个、不会一次性放开一批）、临界判定连跑 20 轮逐位一致；
- **无效请求不计费**：伪造签名/缺头/时间戳超窗/未知客户端共 80 次乱打后，真实客户端的完整配额一个不少；重放（409）与越权（403）也不占额度；
- **并发配额**：32 并发冲容量 3 的桶恰好 3 个 200、其余 429；同一客户端两个 scope 各 32 并发交叉，各自恰好放过 3 个，跨范围计数不串。

测试日志对每个请求打印 `requestId`、`clientId`、`scope`、命中的桶（`bucket=scope|default`）
与剩余名额 `remaining`，以及判定依据
（`auth accepted ... reason=signature_ok` / `access rejected ... code=... reason=...`），
可在 `target/surefire-reports/` 或控制台中按 requestId 追溯每个请求归属的客户端与范围。

### 5.2 手工冒烟

```bash
# 一键脚本：启动服务 → 成功请求/错误签名/重放/越权/限流 → 关闭服务
scripts/local-verify.sh
```

或手动启动后参考第 2.3 节用 curl 调用。
