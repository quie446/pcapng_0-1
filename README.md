# pcapng-cli

一个从零手写（不链接 libpcap、无第三方依赖）的 pcapng 命令行小工具。
按块流式扫描，任意时刻内存里只有一个块，117MB 文件实测峰值 RSS 约 10MB。

## 功能

- 识别 **Section Header Block (SHB)**、**Interface Description Block (IDB)**、
  **Enhanced Packet Block (EPB)**、**Simple Packet Block (SPB)**；
  SPB 没有时间戳也正常列出（标 `N/A`），不会被当成坏块跳过。
  其它块类型（NRB / ISB / DSB 等）识别类型后安全跳过。
- 自动判定小端 / 大端字节序，解析 `if_name`、`if_tsresol`（10 进制与 2 进制分辨率）。
- 旧式 microsecond / nanosecond `.pcap` 一律明确报「不是 pcapng」并非零退出。
- 块被截断、块长度非法（<12、非 4 对齐、超过 64MiB 上限）、首尾长度不一致，
  都给出带文件偏移的人话错误并非零退出，绝不硬解到一半才崩。
- **不做** TCP 重组。

## 构建

```bash
go build -o pcapng-cli ./cmd/pcapng-cli
```

需要 Go 1.22+，标准库之外零依赖。

## 用法

```text
pcapng-cli list   FILE
pcapng-cli dump    FILE N [--max BYTES]
pcapng-cli filter  FILE [过滤选项] [--write-out OUT.pcapng]
pcapng-cli stats   FILE
```

### `list`

逐包输出：序号、时间戳（UTC，SPB 为 `N/A`）、抓包长度、接口 ID、接口名
（IDB 没有 `if_name` 时显示 `-`）。

```
$ pcapng-cli list testdata/public/dhcp.pcapng
序号    时间戳(UTC)                     抓包长度   接口ID  接口名
1       2004-12-05T19:16:24.317453Z     314       0       -
2       2004-12-05T19:16:24.317748Z     342       0       -
...
```

### `dump N`

第 N 个包（1 起始，EPB/SPB 统一编号）的 canonical hex dump；
`--max BYTES` 只看前若干字节。序号越界退出码为 2。

```
$ pcapng-cli dump testdata/public/dhcp.pcapng 2 --max 16
第 2 个包（接口 0，时间戳 2004-12-05T19:16:24.317748Z，抓包 342 / 原始 342 字节）:
00000000  00 0b 82 01 fc 42 00 08  74 ad f1 9b 08 00 45 00  .....B..t.....E.
```

### `filter`

以太网类型 + IPv4 五元组粗过滤，各条件之间是「与」；源 / 目端口按方向精确匹配。
自动跳过至多两层 802.1Q VLAN 标签；只对 Ethernet (LINKTYPE_ETHERNET) 链路生效。

| 选项 | 说明 | 示例 |
| --- | --- | --- |
| `--ether-type` | EtherType（十六进制） | `--ether-type 0x0800` |
| `--src-ip` / `--dst-ip` | IPv4 地址 | `--src-ip 10.0.0.1` |
| `--proto` | `tcp` / `udp` / `icmp` 或 0-255 | `--proto udp` |
| `--src-port` / `--dst-port` | TCP/UDP 端口 | `--dst-port 67` |
| `--write-out` | 命中包写成新 pcapng | `--write-out out.pcapng` |

不带 `--write-out` 时列出命中包；带 `--write-out` 时：

- 输出文件每个段包含 **SHB（原文复制）+ 该段全部 IDB + 命中块**，顺序合法、字节序保持原样；
  命中块先写临时假脱机文件，依然不把整文件读进内存；
- **空命中也会生成只含 SHB/IDB 的合法 pcapng 并以 0 退出**；
- 输入文件中途损坏时删除半成品并返回非零。

```
$ pcapng-cli filter dhcp.pcapng --proto udp --dst-port 67
1       2004-12-05T19:16:24.317453Z     314       0       -
3       2004-12-05T19:16:24.387484Z     314       0       -
命中 2 个包
```

### `stats`

总包数、按接口（含接口名、多段分别统计）计数、以及「截断块」次数
（EPB `cap_len < orig_len`，或 SPB 块体短于 `orig_len`）。

```
$ pcapng-cli stats testdata/generated/truncated.pcapng
总包数: 1
按接口计数:
  接口 0 (-): 1 个包
截断块次数: 1
```

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功（含 filter 空命中写头） |
| 1 | 用法错误、不是 pcapng、块损坏 / 截断、IO 错误 |
| 2 | `dump` 包序号越界 |

## 设计

- `internal/pcapng/reader.go` — 块流读取器：先看 4 字节魔数区分 pcapng / 旧式 pcap / 随机数据，
  再用 SHB 内 Byte-Order Magic 选字节序；逐块校验 `total_length` 首尾一致性。
- `internal/pcapng/blocks.go` — SHB / IDB / EPB / SPB 与 TLV 选项解析。
- `internal/pcapng/timestamp.go` — 按 `if_tsresol`（10 进制 / 2 进制）换算时间戳。
- `internal/pcapng/filter.go` — Ethernet（含 QinQ）+ IPv4 + TCP/UDP 粗过滤。
- `internal/pcapng/writer.go` — 过滤结果按段流式落盘（临时假脱机）。
- `cmd/pcapng-cli` — 四个子命令；`cmd/spb-make`、`cmd/make-trunc`、`cmd/gen-big`
  是测试夹具生成工具。

## 测试

```bash
go test ./...                      # 单元测试
bash scripts/acceptance.sh         # 端到端验收（含中间截断拒绝、pcap 拒绝等 15 项）
```

验收所用公开样例（Wireshark 官方 captures）及其许可证见 `testdata/README.md`。

## 不支持

- TCP/UDP 重组、应用层解码；
- NRB/ISB/DSB 等非包块的内容解析（安全跳过）；
- pcapng 之外的格式写出。
