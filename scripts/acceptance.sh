#!/usr/bin/env bash
# 端到端验收：公开样例 + SPB + 旧式 pcap 拒绝 + 中间块截断拒绝 + 空命中写头。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
check() { # check NAME EXPECTED_ACTUAL
  if [ "$2" = "$3" ]; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1 (got '$2' want '$3')"; fail=$((fail+1)); fi
}

CLI="$TMP/pcapng-cli"
(cd "$ROOT" && go build -o "$CLI" ./cmd/pcapng-cli)

PUB="$ROOT/testdata/public"
GEN="$ROOT/testdata/generated"

echo "--- list 公开样例（小端微秒）"
"$CLI" list "$PUB/dhcp.pcapng" >"$TMP/list.txt"
check "4 个包" "$(grep -c '^[0-9]' "$TMP/list.txt")" 4

echo "--- list 公开样例（纳秒分辨率）"
"$CLI" list "$PUB/dhcp-nanosecond.pcapng" | grep -q '317453000Z'
check "纳秒时间戳 9 位小数" $? 0

echo "--- list 公开样例（大端字节序 + if_name）"
"$CLI" list "$PUB/dhcp_big_endian.pcapng" | grep -q 'silly ethernet interface'
check "大端 + 接口名" $? 0

echo "--- SPB（由公开 EPB 样例确定性转换）时间戳必须是 N/A"
"$CLI" list "$GEN/dhcp-spb.pcapng" >"$TMP/spb.txt"
check "SPB 包数" "$(grep -c 'N/A' "$TMP/spb.txt")" 4

echo "--- 旧式 microsecond pcap 必须被明确拒绝"
"$CLI" list "$PUB/dhcp.pcap" >/dev/null 2>"$TMP/err.txt"
rc=$?
check "pcap 退出码非零" "$rc" 1
grep -q '不是 pcapng' "$TMP/err.txt"
check "pcap 人话错误" $? 0

echo "--- 旧式 nanosecond pcap 同样拒绝"
"$CLI" list "$PUB/dhcp-nanosecond.pcap" >/dev/null 2>&1
check "nano pcap 退出码非零" $? 1

echo "--- 中间一块被截断必须拒绝"
python3 - "$PUB/dhcp.pcapng" "$TMP/trunc.pcapng" <<'PY'
import sys
d=open(sys.argv[1],'rb').read()
off=60  # 第一个 EPB 的文件偏移（SHB 28 + IDB 32）
open(sys.argv[2],'wb').write(d[:off+40])  # EPB 只给了 40 字节
PY
"$CLI" list "$TMP/trunc.pcapng" >/dev/null 2>"$TMP/err.txt"
rc=$?
check "截断退出码非零" "$rc" 1
grep -Eq '截断' "$TMP/err.txt"
check "截断人话错误" $? 0

echo "--- dump 越界退出码 2"
"$CLI" dump "$PUB/dhcp.pcapng" 99 >/dev/null 2>&1
check "越界退出码" $? 2

echo "--- filter 粗过滤（UDP 目的 67）"
"$CLI" filter "$PUB/dhcp.pcapng" --proto udp --dst-port 67 >"$TMP/hits.txt"
check "DHCP 命中 2 包" "$(grep -c '^[0-9]' "$TMP/hits.txt")" 2

echo "--- filter 写回：全量写出与原文件字节一致"
"$CLI" filter "$PUB/dhcp.pcapng" --write-out "$TMP/all.pcapng" >/dev/null
cmp -s "$PUB/dhcp.pcapng" "$TMP/all.pcapng"
check "字节级一致" $? 0

echo "--- filter 空命中仍写合法的「只有头」文件并退出 0"
"$CLI" filter "$PUB/dhcp.pcapng" --ether-type 0x0806 --write-out "$TMP/empty.pcapng" >/dev/null
check "空命中退出码" $? 0
"$CLI" stats "$TMP/empty.pcapng" | grep -q '总包数: 0'
check "空文件 stats 为 0" $? 0

echo "--- stats 截断计数"
"$CLI" stats "$GEN/truncated.pcapng" | grep -q '截断块次数: 1'
check "截断次数为 1" $? 0

echo
if [ "$fail" -eq 0 ]; then
  echo "全部通过（$pass 项）"
else
  echo "$fail 项失败"
  exit 1
fi
