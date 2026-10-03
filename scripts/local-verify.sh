#!/usr/bin/env bash
# 本地冒烟验证：启动应用后依次演示
# 正常/错误签名/重放/越权(scope)/跨租户/配额临界/分范围独立/突发余量/无效请求不计费
set -u
cd "$(dirname "$0")/.."

PORT="${SERVER_PORT:-18080}"
BASE="http://localhost:${PORT}"
SECRET_A="secret-a-secret-a-secret-"
SECRET_NOREAD="secret-noread-secret-noread-secret-"
SECRET_LIMITED="secret-limited-secret-limited-secret-"
SECRET_MULTISCOPE="secret-multiscope-secret-multiscope-secret-"
SECRET_BURST="secret-burst-secret-burst-secret-"

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
  # 以本服务特有的 401 错误体（含 AUTH_MISSING_CREDENTIALS）确认是"我们的"应用已就绪，
  # 避免端口被环境里其它服务占用时误判
  if curl -s -X POST "$BASE/api/orders/list" -d '{}' | grep -q 'AUTH_MISSING_CREDENTIALS'; then
    ready=1; break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "应用启动失败，请检查 /tmp/local-verify-app.log（端口 $PORT 可能被占用）" >&2
    exit 1
  fi
  sleep 1
done
if [ "${ready:-0}" != 1 ]; then
  echo "等待应用就绪超时，请检查 /tmp/local-verify-app.log" >&2
  exit 1
fi

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

echo; echo; echo "== 6. 配额临界（client-limited 稳态/突发=3，连发 4 次）"
for i in 1 2 3 4; do
  echo "--- 第 $i 次："
  call client-limited "$SECRET_LIMITED" "nonce-rl-$i-$(date +%s%N)" '{"orderId":"ORD-1001"}'
  echo
done

echo; echo "== 7. 分范围独立（client-multiscope：read 3/3、export 5/8）"
echo "--- 7a. orders:read 连发 4 次（预期 200,200,200,429）"
for i in 1 2 3 4; do
  call client-multiscope "$SECRET_MULTISCOPE" "nonce-read-$i-$(date +%s%N)" '{}' /api/orders/list
  echo
done
echo "--- 7b. read 见底后 orders:export 仍可连发（前 8 个 200，独立计数，不被 read 挤占）"
for i in $(seq 1 9); do
  echo "--- export 第 $i 次："
  call client-multiscope "$SECRET_MULTISCOPE" "nonce-export-$i-$(date +%s%N)" '{}' /api/orders/export
  echo
done

echo; echo "== 8. 突发余量（client-burst：稳态 2/窗口、突发 5；连发 7 次，预期前 5 个 200、后 2 个 429）"
for i in $(seq 1 7); do
  echo "--- burst 第 $i 次："
  call client-burst "$SECRET_BURST" "nonce-burst-$i-$(date +%s%N)" '{}' /api/orders/list
  echo
done

echo; echo "== 9. 无效请求不计费（伪造签名打 client-burst，随后真实额度应仍在）"
for i in $(seq 1 5); do
  ts=$(date +%s); n="nonce-forged-$i-$(date +%s%N)"
  curl -s -o /dev/null -w "forged #$i [HTTP %{http_code}]\n" "$BASE/api/orders/list" \
    -H 'Content-Type: application/json' -H "X-Client-Id: client-burst" \
    -H "X-Timestamp: $ts" -H "X-Nonce: $n" \
    -H "X-Signature: dGhpcy1pcy1hLWJhZC1zaWduYXR1cmU=" -d '{}'
done
echo "（注意：上一节 client-burst 已用掉突发额度；这里的伪造请求全部 401，不会再扣额度。）"

echo; echo "==> 完成，关闭服务"
