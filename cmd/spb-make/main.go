// spb-make converts EPB packets in a pcapng into Simple Packet Blocks.
// It exists to deterministically produce a public SPB test fixture from a
// public EPB capture (Wireshark's test/captures/dhcp.pcapng).
package main

import (
	"fmt"
	"io"
	"os"

	"pcapng/internal/pcapng"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "用法：spb-make IN.pcapng OUT.pcapng")
		os.Exit(1)
	}
	in, err := os.Open(os.Args[1])
	must(err)
	defer in.Close()
	out, err := os.Create(os.Args[2])
	must(err)
	defer out.Close()

	rd := pcapng.NewReader(in)
	for {
		b, err := rd.Next()
		if err == io.EOF {
			return
		}
		must(err)
		switch b.Type {
		case pcapng.TypeSHB, pcapng.TypeIDB:
			_, err = out.Write(raw(b, b.Payload))
			must(err)
		case pcapng.TypeEPB:
			p, err := pcapng.DecodeEPB(b)
			must(err)
			o := b.Order
			padded := (p.Captured + 3) &^ 3
			payload := make([]byte, 4+padded)
			o.PutUint32(payload[0:4], p.Original)
			copy(payload[4:], p.Data)
			spb := &pcapng.Block{Type: pcapng.TypeSPB, Order: o, Payload: payload}
			_, err = out.Write(raw(spb, payload))
			must(err)
		default:
			// Drop blocks that are not SHB/IDB/EPB.
		}
	}
}

func raw(b *pcapng.Block, payload []byte) []byte {
	total := uint32(12 + len(payload))
	out := make([]byte, total)
	b.Order.PutUint32(out[0:4], b.Type)
	b.Order.PutUint32(out[4:8], total)
	copy(out[8:], payload)
	b.Order.PutUint32(out[8+len(payload):], total)
	return out
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}
