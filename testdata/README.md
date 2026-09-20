# 测试数据来源

## public/

以下文件来自 Wireshark 官方公开测试集
<https://github.com/wireshark/wireshark/tree/master/test/captures>，
许可证为 GPL-2.0-or-later，仅用于端到端验收：

- `dhcp.pcapng` — 小端、微秒分辨率 EPB
- `dhcp-nanosecond.pcapng` — `if_tsresol` 纳秒分辨率
- `dhcp_big_endian.pcapng` — 大端字节序，IDB 带 `if_name`
- `dhcp.pcap` / `dhcp-nanosecond.pcap` — 旧式 pcap（microsecond / nanosecond magic），用于验证「不是 pcapng」拒绝路径
- `many_interfaces.pcapng.1` — 11 个 IDB、多接口名（en0/lo0 等）；注意其中 type 5 是 ISB 接口统计块，不是 SPB

## generated/

由仓库内工具从上面的公开样例确定性生成：

- `dhcp-spb.pcapng` — 由 `go run ./cmd/spb-make testdata/public/dhcp.pcapng ...`
  生成，4 个 Simple Packet Block（无时间戳）
- `truncated.pcapng` — 由 `go run ./cmd/make-trunc ...` 生成，
  EPB 抓包长度 100 < 原始长度 512，用于 stats 截断计数
