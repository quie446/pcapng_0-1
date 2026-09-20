# pcapngtool

轻量 pcapng 命令行工具：纯 Go 自解析（不依赖 libpcap），按块流式扫描，
不把整个文件读进内存（实测 164 MB / 200 万包，峰值内存约 10 MB）。

## 构建

```sh
go build -o pcapngtool .
```

## 支持的块类型

- Section Header Block（SHB）：小端 / 大端 section 均可，支持多 section
- Interface Description Block（IDB）：解析 linktype、snaplen、`if_name`、`if_tsresol`
- Enhanced Packet Block（EPB）：时间戳按接口 `if_tsresol` 换算为秒
- Simple Packet Block（SPB）：无时间戳（list 显示 `N/A`），接口隐式为 0
- 其他块（NRB、ISB 等）：跳过

## 子命令

### list — 列出所有包

```sh
./pcapngtool list capture.pcapng
```

输出包序号（1-based）、时间戳（SPB 为 `N/A`）、捕获长度、接口 id、接口名（IDB 有 `if_name` 时）。

### dump — 第 N 个包的 hex

```sh
./pcapngtool dump capture.pcapng 3 [--max 64]
```

N 越界时非零退出；`--max` 限制输出字节数。

### filter — 以太网类型 + IPv4 五元组粗过滤

```sh
./pcapngtool filter capture.pcapng \
    [--ethertype 0x0800] [--src-ip IP] [--dst-ip IP] \
    [--proto tcp|udp|icmp|N] [--src-port P] [--dst-port P] \
    [--write-out out.pcapng]
```

- 字段过滤仅适用于 Ethernet（linktype 1）接口，自动解最多两层 VLAN tag（802.1Q/1ad）
- 端口条件只对 TCP/UDP 生效
- `--write-out` 把命中包连同必要的 SHB/IDB 原样写成新的合法 pcapng；
  空命中时写出「只有头、没有包」的合法文件并以 0 退出

### stats — 统计

```sh
./pcapngtool stats capture.pcapng
```

输出总包数、按接口计数、截断包数（caplen < origlen）。

## 错误处理（均非零退出）

- 误喂经典 `.pcap`（microsecond/nanosecond 四种 magic）：明确报「not a pcapng file」
- 文件中间截断：报「truncated block … file ends mid-block」并给出偏移
- 非法块长度（< 12、头尾长度不一致、EPB caplen 越界）：人话报错

## 验证记录

`testdata/` 内为公开样例（Wireshark 官方测试捕获，
<https://github.com/wireshark/wireshark/tree/master/test/captures>）及自造的 SPB 样例：

- `dhcp.pcapng` / `dhcp-nanosecond.pcapng` / `dhcp_big_endian.pcapng`：小端 / 纳秒分辨率 / 大端
- `dns_icmp.pcapng`：33 包，`filter --proto udp --dst-port 53 --write-out` 命中 6 包，
  产物经 `tcpdump -r` 验证可读；空命中产物为仅含 SHB+IDB 的合法文件
- `spb_sample.pcapng`：含 SPB（list 时间戳列显示 `N/A`）
- `arp.pcap`：经典 pcap，用于验证拒绝路径

截断测试：`head -c 800 testdata/dns_icmp.pcapng > /tmp/truncated.pcapng`，
工具报 `offset 220: truncated block ... file ends mid-block` 并以 1 退出。

不在范围内：TCP 重组、IPv6 五元组、pcapng 压缩。
