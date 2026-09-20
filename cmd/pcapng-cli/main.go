package main

import (
	"fmt"
	"os"
)

const usageText = `pcapng-cli — 自解析、流式读取的 pcapng 小工具（不依赖 libpcap）

用法：
  pcapng-cli list   FILE
  pcapng-cli dump    FILE N [--max BYTES]
  pcapng-cli filter  FILE [过滤选项] [--write-out OUT.pcapng]
  pcapng-cli stats   FILE

filter 过滤选项（粗过滤，可组合，全部命中才算）：
  --ether-type 0x0800   以太网类型（十六进制）
  --src-ip ADDR         IPv4 源地址
  --dst-ip ADDR         IPv4 目的地址
  --proto tcp|udp|icmp|数字
  --src-port N          TCP/UDP 源端口（或目的端口）
  --dst-port N          TCP/UDP 目的端口（或源端口）
  --write-out FILE      把命中包连同 SHB/IDB 写成新的 pcapng；空命中只写头
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "list":
		err = runList(args)
	case "dump":
		err = runDump(args)
	case "filter":
		err = runFilter(args)
	case "stats":
		err = runStats(args)
	case "-h", "--help", "help":
		fmt.Print(usageText)
		return
	default:
		err = fmt.Errorf("未知子命令 %q\n\n%s", cmd, usageText)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%s\n", err.Error())
		os.Exit(1)
	}
}
