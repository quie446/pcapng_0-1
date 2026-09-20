// make-trunc writes a tiny pcapng where the EPB captured length is smaller
// than the on-the-wire original length, exercising stats' truncation count.
package main

import (
	"encoding/binary"
	"os"
)

func main() {
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	o := binary.LittleEndian

	put := func(typ uint32, payload []byte) {
		total := uint32(12 + len(payload))
		h := make([]byte, 12)
		o.PutUint32(h[0:4], typ)
		o.PutUint32(h[4:8], total)
		o.PutUint32(h[8:12], total)
		f.Write(h[:8])
		f.Write(payload)
		f.Write(h[8:])
	}

	shb := make([]byte, 16)
	copy(shb[0:4], []byte{0x4d, 0x3c, 0x2b, 0x1a})
	o.PutUint32(shb[4:8], 1<<16)
	put(0x0a0d0d0a, shb)

	idb := make([]byte, 8)
	o.PutUint16(idb[0:2], 1)   // Ethernet
	o.PutUint32(idb[4:8], 128) // snaplen 128
	put(1, idb)

	frame := make([]byte, 100)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	epb := make([]byte, 20+100)
	o.PutUint32(epb[12:16], 100) // captured 100
	o.PutUint32(epb[16:20], 512) // original 512 -> truncated
	copy(epb[20:], frame)
	put(6, epb)
}
