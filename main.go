package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const usage = `pcapngtool - stream-inspect pcapng capture archives (no libpcap)

Usage:
  pcapngtool list   FILE
  pcapngtool dump   FILE N [--max BYTES]
  pcapngtool filter FILE [--ethertype T] [--src-ip IP] [--dst-ip IP]
                         [--proto tcp|udp|icmp|N] [--src-port P] [--dst-port P]
                         [--write-out OUT.pcapng]
  pcapngtool stats  FILE

Packets are numbered 1-based in file order (EPB and SPB blocks).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		err = cmdList(os.Args[2:])
	case "dump":
		err = cmdDump(os.Args[2:])
	case "filter":
		err = cmdFilter(os.Args[2:])
	case "stats":
		err = cmdStats(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// parseArgs splits interleaved flags and positionals.
// Flags with values: --flag value or --flag=value. No boolean flags exist.
func parseArgs(args []string, flagNames ...string) (map[string]string, []string, error) {
	known := map[string]bool{}
	for _, n := range flagNames {
		known[n] = true
	}
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			name := strings.TrimPrefix(a, "--")
			if eq := strings.Index(name, "="); eq >= 0 {
				if !known[name[:eq]] {
					return nil, nil, fmt.Errorf("unknown flag --%s", name[:eq])
				}
				flags[name[:eq]] = name[eq+1:]
				continue
			}
			if !known[name] {
				return nil, nil, fmt.Errorf("unknown flag --%s", name)
			}
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("flag --%s needs a value", name)
			}
			i++
			flags[name] = args[i]
		} else {
			pos = append(pos, a)
		}
	}
	return flags, pos, nil
}

func openFile(pos []string) (*os.File, error) {
	if len(pos) != 1 {
		return nil, fmt.Errorf("expected exactly one input file\n\n%s", usage)
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return nil, err
	}
	return f, nil
}

func ifaceName(rd *Reader, id uint32) string {
	if int(id) < len(rd.Interfaces()) && rd.Interfaces()[id].Name != "" {
		return rd.Interfaces()[id].Name
	}
	return "-"
}

func cmdList(args []string) error {
	_, pos, err := parseArgs(args)
	if err != nil {
		return err
	}
	f, err := openFile(pos)
	if err != nil {
		return err
	}
	defer f.Close()

	rd := NewReader(f)
	fmt.Printf("%-6s  %-18s  %-10s  %-5s  %s\n", "index", "timestamp", "caplen", "iface", "ifname")
	for {
		pkt, err := rd.NextPacket()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		ts := "N/A"
		if pkt.HasTS {
			ts = strconv.FormatFloat(pkt.Timestamp, 'f', 6, 64)
		}
		fmt.Printf("%-6d  %-18s  %-10d  %-5d  %s\n", pkt.Index, ts, pkt.CapLen, pkt.IfaceID, ifaceName(rd, pkt.IfaceID))
	}
}

func cmdDump(args []string) error {
	flags, pos, err := parseArgs(args, "max")
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("dump needs FILE and packet number N\n\n%s", usage)
	}
	n, err := strconv.Atoi(pos[1])
	if err != nil || n < 1 {
		return fmt.Errorf("invalid packet number %q (1-based)", pos[1])
	}
	maxBytes := -1
	if v, ok := flags["max"]; ok {
		m, err := strconv.Atoi(v)
		if err != nil || m < 0 {
			return fmt.Errorf("invalid --max value %q", v)
		}
		maxBytes = m
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	defer f.Close()

	rd := NewReader(f)
	for {
		pkt, err := rd.NextPacket()
		if err == io.EOF {
			return fmt.Errorf("packet %d out of range (file contains %d packets)", n, rd.pktIndex)
		}
		if err != nil {
			return err
		}
		if pkt.Index != n {
			continue
		}
		data := pkt.Data
		truncated := false
		if maxBytes >= 0 && len(data) > maxBytes {
			data = data[:maxBytes]
			truncated = true
		}
		fmt.Printf("# packet %d: caplen=%d origlen=%d iface=%d", pkt.Index, pkt.CapLen, pkt.OrigLen, pkt.IfaceID)
		if truncated {
			fmt.Printf(" (showing first %d bytes)", maxBytes)
		}
		fmt.Println()
		hexDump(os.Stdout, data)
		return nil
	}
}

func hexDump(w io.Writer, data []byte) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(w, "%08x  ", i)
		for j := i; j < end; j++ {
			fmt.Fprintf(w, "%02x ", data[j])
			if j%8 == 7 {
				fmt.Fprint(w, " ")
			}
		}
		fmt.Fprintln(w)
	}
}

func cmdFilter(args []string) error {
	flags, pos, err := parseArgs(args, "ethertype", "src-ip", "dst-ip", "proto", "src-port", "dst-port", "write-out")
	if err != nil {
		return err
	}
	f, err := openFile(pos)
	if err != nil {
		return err
	}
	defer f.Close()

	flt := &Filter{}
	if v, ok := flags["ethertype"]; ok {
		et, err := parseUint16(v)
		if err != nil {
			return fmt.Errorf("--ethertype: %w", err)
		}
		flt.EtherType = &et
	}
	if v, ok := flags["src-ip"]; ok {
		ip := parseIPv4(v)
		if ip == nil {
			return fmt.Errorf("--src-ip: invalid IPv4 address %q", v)
		}
		flt.SrcIP = ip
	}
	if v, ok := flags["dst-ip"]; ok {
		ip := parseIPv4(v)
		if ip == nil {
			return fmt.Errorf("--dst-ip: invalid IPv4 address %q", v)
		}
		flt.DstIP = ip
	}
	if v, ok := flags["proto"]; ok {
		p, err := parseProto(v)
		if err != nil {
			return err
		}
		flt.Proto = &p
	}
	if v, ok := flags["src-port"]; ok {
		p, err := parseUint16(v)
		if err != nil {
			return fmt.Errorf("--src-port: %w", err)
		}
		flt.SrcPort = &p
	}
	if v, ok := flags["dst-port"]; ok {
		p, err := parseUint16(v)
		if err != nil {
			return fmt.Errorf("--dst-port: %w", err)
		}
		flt.DstPort = &p
	}

	var out *os.File
	if path, ok := flags["write-out"]; ok {
		out, err = os.Create(path)
		if err != nil {
			return err
		}
		defer out.Close()
	}

	rd := NewReader(f)
	matched, total := 0, 0
	for {
		blk, err := rd.NextBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch blk.Type {
		case BlockTypeSHB, BlockTypeIDB:
			if blk.Type == BlockTypeIDB {
				iface, err := parseIDB(rd.bo, blk.Body)
				if err != nil {
					return fmt.Errorf("offset %d: %w", blk.Offset, err)
				}
				rd.ifaces = append(rd.ifaces, iface)
			}
			if out != nil {
				if _, err := out.Write(blk.Raw); err != nil {
					return err
				}
			}
		case BlockTypeEPB, BlockTypeSPB:
			rd.pktIndex++
			var pkt *Packet
			if blk.Type == BlockTypeEPB {
				pkt, err = rd.parseEPB(blk)
			} else {
				pkt, err = rd.parseSPB(blk)
			}
			if err != nil {
				return err
			}
			pkt.Index = rd.pktIndex
			total++
			linkType := uint16(0)
			if int(pkt.IfaceID) < len(rd.ifaces) {
				linkType = rd.ifaces[pkt.IfaceID].LinkType
			}
			if flt.Match(pkt, linkType) {
				matched++
				ts := "N/A"
				if pkt.HasTS {
					ts = strconv.FormatFloat(pkt.Timestamp, 'f', 6, 64)
				}
				fmt.Printf("match packet %-6d ts=%-18s caplen=%-6d iface=%d\n", pkt.Index, ts, pkt.CapLen, pkt.IfaceID)
				if out != nil {
					if _, err := out.Write(pkt.Raw); err != nil {
						return err
					}
				}
			}
		}
	}
	fmt.Printf("filter: %d/%d packets matched\n", matched, total)
	if out != nil {
		if err := out.Sync(); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d matched packets, header-only if 0)\n", flags["write-out"], matched)
	}
	return nil
}

func cmdStats(args []string) error {
	_, pos, err := parseArgs(args)
	if err != nil {
		return err
	}
	f, err := openFile(pos)
	if err != nil {
		return err
	}
	defer f.Close()

	rd := NewReader(f)
	perIface := map[uint32]int{}
	var order []uint32
	total, truncated := 0, 0
	for {
		pkt, err := rd.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		total++
		if _, seen := perIface[pkt.IfaceID]; !seen {
			order = append(order, pkt.IfaceID)
		}
		perIface[pkt.IfaceID]++
		if pkt.CapLen < pkt.OrigLen {
			truncated++
		}
	}
	fmt.Printf("total packets: %d\n", total)
	fmt.Println("per-interface counts:")
	for _, id := range order {
		fmt.Printf("  iface %d (%s): %d\n", id, ifaceName(rd, id), perIface[id])
	}
	fmt.Printf("truncated packets (caplen < origlen): %d\n", truncated)
	return nil
}

func parseIPv4(s string) []byte {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	ip := make([]byte, 4)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil
		}
		ip[i] = byte(v)
	}
	return ip
}
