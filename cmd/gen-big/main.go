// gen-big streams a large multi-section pcapng to disk for verifying the
// reader's block-at-a-time memory behavior without loading the whole file.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "用法：gen-big OUT.pcapng PACKETS")
		os.Exit(1)
	}
	var n int
	fmt.Sscanf(os.Args[2], "%d", &n)
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	o := binary.LittleEndian

	write := func(typ uint32, payload []byte) {
		total := uint32(12 + len(payload))
		hdr := make([]byte, 12)
		o.PutUint32(hdr[0:4], typ)
		o.PutUint32(hdr[4:8], total)
		o.PutUint32(hdr[8:12], total)
		if _, err := f.Write(hdr[:8]); err != nil {
			panic(err)
		}
		if _, err := f.Write(payload); err != nil {
			panic(err)
		}
		if _, err := f.Write(hdr[8:]); err != nil {
			panic(err)
		}
	}

	shb := func() {
		p := make([]byte, 16)
		copy(p[0:4], []byte{0x4d, 0x3c, 0x2b, 0x1a})
		o.PutUint32(p[4:8], 1<<16)
		write(0x0a0d0d0a, p)
	}
	idb := func() {
		p := make([]byte, 8)
		o.PutUint16(p[0:2], 1)
		o.PutUint32(p[4:8], 262144)
		write(1, p)
	}
	shb()
	idb()
	frame := make([]byte, 1200)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // EtherType IPv4
	frame[14] = 0x45                                 // version=4, IHL=5
	frame[15] = 0x00
	binary.BigEndian.PutUint16(frame[16:18], uint16(len(frame)-14))
	frame[23] = 6                                  // TCP
	binary.BigEndian.PutUint16(frame[54:56], 443)  // TCP dest port
	binary.BigEndian.PutUint16(frame[56:58], 8080) // TCP source port
	for i := 0; i < n; i++ {
		p := make([]byte, 20+len(frame))
		o.PutUint32(p[0:4], 0) // interface id
		o.PutUint32(p[12:16], uint32(len(frame)))
		o.PutUint32(p[16:20], uint32(len(frame)))
		copy(p[20:], frame)
		write(6, p)
	}
	// Second section exercises multi-section handling.
	shb()
	idb()
}
