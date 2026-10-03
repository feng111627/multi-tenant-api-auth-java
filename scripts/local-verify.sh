#!/usr/bin/env bash
# 本地冒烟验证：启动应用后依次演示 正常/错误签名/重放/越权(scope)/跨租户/限流
set -u
cd "$(dirname "$0")/.."

PORT="${VERIFY_PORT:-19090}"
BASE="http://localhost:${PORT}"
SECRET_A="secret-a-secret-a-secret-"
SECRET_NOREAD="secret-noread-secret-noread-secret-"
SECRET_LIMITED="secret-limited-secret-limited-secret-"
SECRET_SCOPED="secret-test-secret-test-secret-0"

if ! command -v openssl >/dev/null || ! command -v curl >/dev/null; then
  echo "需要 openssl 与 curl" >&2
  exit 1
fi

echo "==> 打包"
mvn -q -DskipTests package || { echo "打包失败"; exit 1; }

JAR=$(ls target/multi-tenant-api-auth-java-*.jar | head -1)
echo "==> 启动 $JAR (端口 $PORT)"
SERVER_PORT=$PORT java -jar "$JAR" >/tmp/local-verify-app.log 2>&1 &
PID=$!
trap 'kill $PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 1
done

call() {
  local client_id="$1" secret="$2" nonce="$3" body="$4" path="${5:-/api/orders/get}"
  local ts body_hash canon sig
  ts=$(date +%s)
  body_hash=$(printf '%s' "$body" | openssl dgst -sha256 | awk '{print $NF}')
  canon=$(printf 'POST\n%s\n%s\n%s\n%s' "$path" "$ts" "$nonce" "$body_hash")
  sig=$(printf '%s' "$canon" | openssl dgst -sha256 -hmac "$secret" -binary | base64 -w0)
  curl -s -w '\n[HTTP %{http_code}]' "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-Client-Id: $client_id" \
    -H "X-Timestamp: $ts" \
    -H "X-Nonce: $nonce" \
    -H "X-Signature: $sig" \
    -d "$body"
}

echo; echo "== 1. 正常请求（client-a 查自己的订单）"
call client-a "$SECRET_A" "nonce-$(date +%s%N)" '{"orderId":"ORD-1001"}'

echo; echo; echo "== 2. 错误签名"
ts=$(date +%s); n="nonce-bad-$(date +%s%N)"
curl -s -w '\n[HTTP %{http_code}]' "$BASE/api/orders/get" \
  -H 'Content-Type: application/json' -H "X-Client-Id: client-a" \
  -H "X-Timestamp: $ts" -H "X-Nonce: $n" \
  -H "X-Signature: dGhpcy1pcy1hLWJhZC1zaWduYXR1cmU=" \
  -d '{"orderId":"ORD-1001"}'

echo; echo; echo "== 3. 重放（同一 nonce 连打两次）"
RN="nonce-replay-$(date +%s%N)"
call client-a "$SECRET_A" "$RN" '{"orderId":"ORD-1001"}'
echo; echo "--- 第二次："
call client-a "$SECRET_A" "$RN" '{"orderId":"ORD-1001"}'

echo; echo; echo "== 4. scope 越权（client-noread 没有 orders:read）"
call client-noread "$SECRET_NOREAD" "nonce-$(date +%s%N)" '{"orderId":"ORD-1001"}'

echo; echo; echo "== 5. 数据归属越权（client-a 查 tenant-b 的 ORD-2001）"
call client-a "$SECRET_A" "nonce-$(date +%s%N)" '{"orderId":"ORD-2001"}'

echo; echo; echo "== 6. 默认窗口限流（client-limited 限额 3，连发 4 次）"
for i in 1 2 3 4; do
  echo "--- 第 $i 次："
  call client-limited "$SECRET_LIMITED" "nonce-rl-$i-$(date +%s%N)" '{"orderId":"ORD-1001"}'
  echo
done

echo; echo "== 7. 分范围配额（client-scoped：orders:read 稳态2+突发2=4）"
for i in 1 2 3 4 5; do
  echo "--- orders:read 第 $i 次（前 4 次 200，第 5 次 429）："
  call client-scoped "$SECRET_SCOPED" "nonce-read-$i-$(date +%s%N)" '{}' /api/orders/list
  echo
done
echo "--- orders:ping 是另一本账（容量 5，不受 read 打空影响），连发 6 次："
for i in 1 2 3 4 5 6; do
  echo "--- ping 第 $i 次："
  call client-scoped "$SECRET_SCOPED" "nonce-ping-$i-$(date +%s%N)" '{}' /api/orders/ping
  echo
done

echo; echo "==> 完成，关闭服务"
