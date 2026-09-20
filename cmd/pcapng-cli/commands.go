package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"pcapng/internal/pcapng"
)

func interfaceName(p *pcapng.Packet, st *scanState) string {
	iface := st.iface(p)
	if iface != nil && iface.Name != "" {
		return iface.Name
	}
	return "-"
}

func runList(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法：pcapng-cli list FILE")
	}
	return scan(args[0], sectionVisitor{
		onPacket: func(b *pcapng.Block, p *pcapng.Packet, st *scanState) error {
			fmt.Print(packetHeader(p.Index))
			ts := pcapng.Timestamp(p, st.iface(p))
			fmt.Printf(listRow, p.Index, ts, p.Captured, p.Interface, interfaceName(p, st))
			return nil
		},
	})
}

func runDump(args []string) error {
	max := -1
	var positional []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--max":
			if i+1 >= len(args) {
				return fmt.Errorf("--max 缺少字节数")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				return fmt.Errorf("--max 需要非负整数，得到 %q", args[i+1])
			}
			max = n
			i++
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) != 2 {
		return fmt.Errorf("用法：pcapng-cli dump FILE N [--max BYTES]")
	}
	n, err := strconv.Atoi(positional[1])
	if err != nil || n < 1 {
		return fmt.Errorf("包序号必须是正整数，得到 %q", positional[1])
	}

	found := false
	err = scan(positional[0], sectionVisitor{
		onPacket: func(b *pcapng.Block, p *pcapng.Packet, st *scanState) error {
			if p.Index != n {
				return nil
			}
			found = true
			fmt.Printf("第 %d 个包（接口 %d，时间戳 %s，抓包 %d / 原始 %d 字节）:\n",
				p.Index, p.Interface, pcapng.Timestamp(p, st.iface(p)), p.Captured, p.Original)
			if err := pcapng.HexDump(os.Stdout, p.Data, max); err != nil {
				return err
			}
			return errStop
		},
	})
	if err == errStop {
		err = nil
	}
	if err != nil {
		return err
	}
	if !found {
		os.Exit(2)
	}
	return nil
}

var errStop = io.EOF

func runStats(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法：pcapng-cli stats FILE")
	}
	type ifaceKey struct{ section, id int }
	total, truncated := 0, 0
	counts := map[ifaceKey]int{}
	names := map[ifaceKey]string{}
	maxID := map[int]int{}
	section := -1

	err := scan(args[0], sectionVisitor{
		onSHB: func(b *pcapng.Block, st *scanState) error {
			section++
			return nil
		},
		onIDB: func(b *pcapng.Block, iface *pcapng.Interface) error {
			key := ifaceKey{section, iface.Index}
			names[key] = iface.Name
			if iface.Index > maxID[section] {
				maxID[section] = iface.Index
			}
			return nil
		},
		onPacket: func(b *pcapng.Block, p *pcapng.Packet, st *scanState) error {
			total++
			key := ifaceKey{section, p.Interface}
			counts[key]++
			if p.Interface > maxID[section] {
				maxID[section] = p.Interface
			}
			if p.Truncated {
				truncated++
			}
			return nil
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("总包数: %d\n", total)
	fmt.Println("按接口计数:")
	for sec := 0; sec <= section; sec++ {
		if section > 0 {
			fmt.Printf("  [段 %d]\n", sec)
		}
		for id := 0; id <= maxID[sec]; id++ {
			name := names[ifaceKey{sec, id}]
			if name == "" {
				name = "-"
			}
			indent := "  "
			if section > 0 {
				indent = "    "
			}
			fmt.Printf("%s接口 %d (%s): %d 个包\n", indent, id, name, counts[ifaceKey{sec, id}])
		}
	}
	fmt.Printf("截断块次数: %d\n", truncated)
	return nil
}
