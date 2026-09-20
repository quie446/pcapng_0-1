package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"pcapng/internal/pcapng"
)

func runFilter(args []string) error {
	fs := flag.NewFlagSet("filter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	etherHex := fs.String("ether-type", "", "以太网类型，如 0x0800")
	srcIP := fs.String("src-ip", "", "IPv4 源地址")
	dstIP := fs.String("dst-ip", "", "IPv4 目的地址")
	proto := fs.String("proto", "", "tcp|udp|icmp 或 IP 协议号")
	srcPort := fs.Int("src-port", 0, "TCP/UDP 源端口（精确）")
	dstPort := fs.Int("dst-port", 0, "TCP/UDP 目的端口（精确）")
	writeOut := fs.String("write-out", "", "把命中包写成新的 pcapng 文件")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法：pcapng-cli filter FILE [过滤选项] [--write-out OUT.pcapng]")
		fs.PrintDefaults()
	}
	ordered, err := reorderFlags(args, filterTakesValue)
	if err != nil {
		return err
	}
	if err := fs.Parse(ordered); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("用法：pcapng-cli filter FILE [过滤选项] [--write-out OUT.pcapng]")
	}

	crit := &pcapng.Criteria{}
	if *etherHex != "" {
		t, err := parseEtherType(*etherHex)
		if err != nil {
			return err
		}
		crit.EtherType = t
		crit.HasEth = true
	}
	if *srcIP != "" {
		a, err := netip.ParseAddr(*srcIP)
		if err != nil || !a.Is4() {
			return fmt.Errorf("--src-ip 需要合法 IPv4 地址，得到 %q", *srcIP)
		}
		crit.SrcIP = a
	}
	if *dstIP != "" {
		a, err := netip.ParseAddr(*dstIP)
		if err != nil || !a.Is4() {
			return fmt.Errorf("--dst-ip 需要合法 IPv4 地址，得到 %q", *dstIP)
		}
		crit.DstIP = a
	}
	if *proto != "" {
		p, err := parseProto(*proto)
		if err != nil {
			return err
		}
		crit.IPProto = p
		crit.HasProto = true
	}
	if *srcPort != 0 {
		if *srcPort < 1 || *srcPort > 65535 {
			return fmt.Errorf("--src-port 超出 1-65535 范围")
		}
		crit.SrcPort = uint16(*srcPort)
		crit.HasPort = true
	}
	if *dstPort != 0 {
		if *dstPort < 1 || *dstPort > 65535 {
			return fmt.Errorf("--dst-port 超出 1-65535 范围")
		}
		crit.DstPort = uint16(*dstPort)
		crit.HasPort = true
	}

	inPath := fs.Arg(0)

	var out *os.File
	var bw *bufio.Writer
	if *writeOut != "" {
		if samePath(inPath, *writeOut) {
			return fmt.Errorf("--write-out 不能与输入文件是同一个文件")
		}
		f, err := os.Create(*writeOut)
		if err != nil {
			return fmt.Errorf("无法创建输出文件 %q：%w", *writeOut, err)
		}
		out = f
		bw = bufio.NewWriterSize(f, 1<<20)
	}

	var sw *pcapng.SectionWriter
	matched := 0

	finishSection := func() error {
		if sw == nil {
			return nil
		}
		n, err := sw.Finish()
		sw = nil
		matched += n
		return err
	}

	scanErr := scan(inPath, sectionVisitor{
		onSHB: func(b *pcapng.Block, st *scanState) error {
			if err := finishSection(); err != nil {
				return err
			}
			if out != nil {
				w, err := pcapng.NewSectionWriter(bw, b)
				if err != nil {
					return err
				}
				sw = w
			}
			return nil
		},
		onIDB: func(b *pcapng.Block, iface *pcapng.Interface) error {
			if sw != nil {
				return sw.AddIDB(b)
			}
			return nil
		},
		onPacket: func(b *pcapng.Block, p *pcapng.Packet, st *scanState) error {
			linkType := uint16(1) // 缺省链路类型即 Ethernet
			if iface := st.iface(p); iface != nil {
				linkType = iface.LinkType
			}
			if !crit.Match(p.Data, linkType) {
				return nil
			}
			if sw != nil {
				if err := sw.AddPacket(b); err != nil {
					return err
				}
			} else {
				if matched == 0 {
					fmt.Printf(listHeader, "序号", "时间戳(UTC)", "抓包长度", "接口ID", "接口名")
				}
				matched++
				fmt.Printf(listRow, p.Index, pcapng.Timestamp(p, st.iface(p)), p.Captured, p.Interface, interfaceName(p, st))
			}
			return nil
		},
	})

	if scanErr != nil {
		if sw != nil {
			sw.Abort()
		}
		if out != nil {
			out.Close()
			os.Remove(*writeOut)
		}
		return scanErr
	}
	if err := finishSection(); err != nil {
		if out != nil {
			out.Close()
			os.Remove(*writeOut)
		}
		return err
	}
	if out != nil {
		if err := bw.Flush(); err != nil {
			out.Close()
			return fmt.Errorf("写出失败：%w", err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("关闭输出文件失败：%w", err)
		}
	}

	if out == nil {
		fmt.Printf("命中 %d 个包\n", matched)
	} else {
		fmt.Fprintf(os.Stderr, "已写出 %d 个命中包到 %s（空命中时文件只含 SHB/IDB 头）\n", matched, *writeOut)
	}
	return nil
}

func parseEtherType(s string) (uint16, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	n, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("--ether-type 需要十六进制数（如 0x0800），得到 %q", s)
	}
	return uint16(n), nil
}

func parseProto(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "icmp":
		return 1, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 255 {
		return 0, fmt.Errorf("--proto 需要 tcp|udp|icmp 或 0-255 的数字，得到 %q", s)
	}
	return uint8(n), nil
}

func samePath(a, b string) bool {
	pa, err1 := filepath.Abs(a)
	pb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return pa == pb
}

// reorderFlags moves flag tokens (and their values) before positional
// arguments so "filter FILE --proto udp" parses the same as the reverse.
func reorderFlags(args []string, takesValue map[string]bool) ([]string, error) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) >= 2 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				flags = append(flags, a)
				continue
			}
			flags = append(flags, a)
			if takesValue[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	if len(positional) > 1 {
		return nil, fmt.Errorf("多余的位置参数：%v（只需要一个 FILE）", positional[1:])
	}
	return append(flags, positional...), nil
}

var filterTakesValue = map[string]bool{
	"ether-type": true,
	"src-ip":     true,
	"dst-ip":     true,
	"proto":      true,
	"src-port":   true,
	"dst-port":   true,
	"write-out":  true,
}
