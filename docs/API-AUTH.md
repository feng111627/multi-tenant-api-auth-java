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
7. **配额**：范围单独配了额度按「客户端 × 范围」令牌桶判定，否则计入客户端共享的
   默认额度（老配置为固定窗口，显式突发为共享令牌桶），超额 `RATE_LIMITED`；
8. **数据归属控制**：业务层从 `ClientContext`（ThreadLocal，请求结束即清理）取 `owner`，所有数据查询强制带 owner 过滤。即使知道他人资源 ID，也查不到数据，也无法在列表中看到他人数据。

> **配额在验签与范围校验通过之后才计数**：任何未通过身份/签名/时间戳/重放/范围校验的请求
> 都会在占用名额之前被拒绝。因此攻击者即便知道一个真实 `clientId` 并伪造大量请求，
> 也无法消耗该客户端真正可用的额度，更不会被算到别的客户端头上——配额桶的键固定为
> 服务端确认过的 `clientId` 与接口 `scope`。

### 配额模型（默认额度 + 分范围额度）

每个客户端有且只有**一份默认额度**（`rateLimit`/`burstLimit`），另外可以按接口范围
单独配置 `scopeQuotas`。二者的关系：

- **范围单独配置了配额** → 该范围使用自己独立的 `(clientId, scope)` 令牌桶，
  各范围各算各的账、互不挤占，也不占用默认额度；
- **范围没有单独配置** → 回落到客户端默认额度。默认额度**整个客户端只有一份**：
  所有回落到它的范围共用同一份预算，跨范围合计严格不超过默认额度——
  不会出现"授了 N 个范围就放大成 N 份默认额度"的情况。

默认额度按客户端是否显式配置 `burstLimit` 分两种计量方式：

- **显式配置了 `burst-limit`（共享令牌桶）**：容量 `burstLimit`、初始为满，
  每 `rate-window-seconds` 匀速补充 `rateLimit` 个令牌。短时间冲一波不超过
  `burstLimit` 就整波放行；见底即 429，随后按稳态速率逐枚补充、平滑回收，
  不会出现"长时间一个不放、然后一次性放开一大片"的抖动；
- **只配了 `rate-limit`、没配 `burst-limit`（老配置 → 共享固定窗口）**：
  整个客户端一个窗口计数器，窗口以请求到达时间锚定，每窗口严格最多放行
  `rateLimit` 个，窗口期满后下一个请求立即开启新窗口。这与"按范围拆分配额"
  上线前的行为**逐点一致**（见下节"老配置兼容性"）。

### 老配置兼容性（升级后哪些变、哪些不变）

针对"只配 `rate-limit`、没配 `burst-limit`、也没配 `scope-quotas`"的老客户端：

| 场景 | 拆分前 | 拆分后（含本次修复） |
| --- | --- | --- |
| 只授了一个范围 | 客户端级固定窗口，`rateLimit`/窗口 | **不变**：同一份客户端级固定窗口 |
| 授了多个范围、都没单独配额 | 整个客户端共用一份 `rateLimit`/窗口 | **不变**：所有范围共用同一份固定窗口，跨范围合计不超发 |
| 窗口切换时机 | 窗口期满立即重置，下一批 `rateLimit` 个立即可用；窗口中途不多放 | **不变**：同一固定窗口实现，同一批请求在相同时间点重跑结果完全一致 |
| 显式配置了 `burst-limit` | （新能力，老配置不涉及） | 默认额度变为客户端级共享令牌桶：突发整波放行、见底即拒、按稳态速率平滑回收 |
| 配置了 `scope-quotas` | （新能力，老配置不涉及） | 被配置的范围各自独立令牌桶，互不影响默认额度 |

### 并发安全

- 客户端身份只存在 `ThreadLocal` 中，并在 `afterCompletion` 中无条件清理，线程池复用线程也不会身份串号；
- 重放判定使用 `ConcurrentHashMap.compute` 原子完成，相同 nonce 并发提交有且仅有一个请求通过（有专项测试）；
- 配额令牌桶以 `(clientId, scope)` 为键、老配置固定窗口以 `clientId` 为键，存放在
  `ConcurrentHashMap` 中；桶内"补充 → 判定 → 扣减"在同一把锁内一次完成，窗口的
  "取窗口 / 期满重开"由 `compute` 原子完成；令牌以整数毫令牌（×1000）运算、不使用浮点，
  因此并发压到边界（恰好最后一个放行、下一个拒绝）的结果与线程调度无关，重跑严格一致；
- 桶/窗口只在请求通过身份与签名校验后创建，`scope` 取自服务端注解，伪造标识无法制造
  限流状态，状态总数有界。

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
| `app.auth.rate-window-seconds` | `60` | 配额稳态窗口长度（秒）：令牌桶的补充周期 / 老配置固定窗口的窗口长度 |
| `app.auth.clients.<id>.secret` | - | Base64 HMAC 密钥（必填） |
| `app.auth.clients.<id>.owner` | - | 数据归属标识（必填） |
| `app.auth.clients.<id>.scopes[n]` | 空 | 授予的接口范围列表 |
| `app.auth.clients.<id>.rate-limit` | `100` | 默认稳态速率：每窗口稳定请求数；未单独配置的范围共同分享这一份默认额度 |
| `app.auth.clients.<id>.burst-limit` | 未配置 | 默认突发上限（共享令牌桶容量）。**留空即老配置**：默认额度按客户端级共享固定窗口计量（每窗口严格 `rate-limit` 个，与拆分前一致）；**显式配置**则默认额度按客户端级共享令牌桶计量 |
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

- 只写 `rate-limit` 完全照旧可用：默认额度按"客户端级共享固定窗口"计量，
  每窗口严格 `rate-limit` 个、窗口期满立即重置，与拆分前逐点一致；
- 默认额度整个客户端只有一份：授了多个范围但都没配 `scope-quotas` 时，
  这些范围共用同一份默认额度，跨范围合计不超发；
- 稳态窗口 `rate-window-seconds` 同时用作共享令牌桶的补充周期与固定窗口的
  窗口长度，无需新增时间配置。

内置示例客户端：

| clientId | owner | scopes | 默认稳态/突发 | 分范围配额 | 用途 |
| --- | --- | --- | --- | --- | --- |
| `client-a` | `tenant-a` | `orders:read` | 1000 / 未配（固定窗口） | 无 | 正常客户端 A |
| `client-b` | `tenant-b` | `orders:read` | 1000 / 未配（固定窗口） | 无 | 正常客户端 B |
| `client-limited` | `tenant-a` | `orders:read` | **3** / 未配（固定窗口） | 无 | 配额临界值验证（老用例） |
| `client-noread` | `tenant-a` | 无 | 1000 / 未配（固定窗口） | 无 | scope 越权验证 |
| `client-multiscope` | `tenant-a` | `orders:read`、`orders:export` | 100 / 未配（固定窗口） | read **3/3**、export **5/8** | 分范围独立、跨范围不串 |
| `client-burst` | `tenant-a` | `orders:read`、`orders:export` | **2 / 5**（共享令牌桶） | 无 | 突发整波放行与边界并发；两范围共用一份默认突发桶 |
| `client-legacy` | `tenant-a` | `orders:read`、`orders:export` | **4** / 未配（固定窗口） | 无 | 老配置兼容：多范围共享一份默认额度 |

> 生产环境请通过环境变量/配置中心下发密钥，并更换示例密钥。

## 5. 本地验证

### 5.1 自动化测试（推荐，结果稳定可复现）

```bash
mvn test
```

覆盖场景（44 个用例，按测试类组织，运行日志中每个类名即业务域）：

- `SignatureVerificationTest`：验签成功 / 缺鉴权头 / 未知客户端 / 签名错误 /
  签名与 body 不匹配；时间戳超窗拒绝、±3 秒时钟偏差放行；
  相同 nonce 重放拒绝、不同客户端共用 nonce 不判重放；
- `AccessControlTest`：scope 不足拒绝、按 ID 越权查他人数据、列表数据不泄露；
- `RateLimitTest`：配额临界值（前 3 个放行、第 4 个 429）、配额按客户端隔离；
- `ConcurrencyTest`：两个客户端 48 个并发请求交叉不串号；相同 nonce 16 并发仅 1 个通过；
- `QuotaServiceTest`（令牌桶单元测试，可控时钟，结果确定可复现）：突发容量整波放行与
  见底即拒、按稳态速率平滑回收（不成片放开）、空闲再久也封顶在突发容量、
  同毫秒并发压界恰好放满容量（连跑多轮结果一致）、不同客户端/不同范围/组合键不串桶、
  rate=0 永不放行；
- `SharedFixedWindowQuotaTest`（老配置共享固定窗口单元测试，可控时钟）：每窗口严格
  limit 个、窗口中途不渗出、期满立即开新窗口；连续多窗口稳态恒为 limit/窗口；
  同一时间序列重跑两次放行/拒绝序列完全一致；并发压界恰好 limit 个（多轮一致）；
  按客户端隔离且与令牌桶互不串账；limit=0 永不放行；
- `ScopedQuotaIntegrationTest`（分范围独立）：同一客户端 read 见底不影响 export，
  二者各按各的容量计数；两范围 64 个并发交叉，read 恰好成 3、export 恰好成 8；
- `BurstQuotaIntegrationTest`（突发余量）：突发整波放行、见底即拒；
  24 并发压界恰好放满突发容量（多轮一致）；
- `LegacySharedQuotaIntegrationTest`（老配置兼容）：多范围未单独配置时跨范围合计
  共用一份默认额度（合并计量）；跨范围并发压界恰好放满共享额度；显式突发的客户端
  多个范围共用同一份默认突发桶；伪造签名/未知客户端/缺头/过期时间戳不占共享默认额度；
- `QuotaAbuseIntegrationTest`（无效请求不计费）：伪造签名 / 未知 clientId / 缺头 /
  过期时间戳乱打一批，真实客户端的额度一个都不少；scope 越权请求也不占额度。

每个请求在日志中都能看到归属的**客户端与接口范围**，便于按维度追溯：

- 通过：`access granted clientId=... scope=orders:read requestId=... owner=...`；
- 拒绝：`access rejected clientId=... scope=... code=... reason=...`；
- 配额见底：`quota exhausted clientId=... scope=... rate=... burst=... window=...s sharedDefault=...`
  （`sharedDefault=true` 表示这次计的是客户端共享默认额度，而非范围独立额度）。

可在 `target/surefire-reports/` 或控制台中按 `requestId`/`clientId`/`scope` 追溯。

### 5.2 手工冒烟

```bash
# 一键脚本：启动服务 → 成功请求/错误签名/重放/越权/限流/分范围/突发/老配置共享额度 → 关闭服务
scripts/local-verify.sh
```

脚本中与本次修复直接相关的两节：

- **老配置多范围共享默认额度**：`client-legacy`（read+export、只配 `rate-limit=4`）
  交替打两个范围 6 次，预期前 4 个 200、后 2 个 429——跨范围合计只有一份默认额度；
- **显式突发的共享默认桶**：`client-burst`（read+export、突发 5）先打 3 次 read
  再打 3 次 export，预期 export 第 3 次（合计第 6 个）429——两个范围共用同一突发桶。

或手动启动后参考第 2.3 节用 curl 调用。
