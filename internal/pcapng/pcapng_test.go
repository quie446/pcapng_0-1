package pcapng

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

type builder struct {
	order binary.ByteOrder
	buf   bytes.Buffer
}

func (b *builder) block(typ uint32, payload []byte) {
	total := uint32(12 + len(payload))
	hdr := make([]byte, 8)
	b.order.PutUint32(hdr[0:4], typ)
	b.order.PutUint32(hdr[4:8], total)
	b.buf.Write(hdr)
	b.buf.Write(payload)
	trailer := make([]byte, 4)
	b.order.PutUint32(trailer, total)
	b.buf.Write(trailer)
}

func (b *builder) shb() {
	magic := []byte{0x4d, 0x3c, 0x2b, 0x1a}
	if b.order == binary.BigEndian {
		magic = []byte{0x1a, 0x2b, 0x3c, 0x4d}
	}
	payload := make([]byte, 16)
	copy(payload[0:4], magic)
	b.order.PutUint32(payload[4:8], 1<<16) // version 1.0
	b.block(TypeSHB, payload)
}

func (b *builder) idb(linkType uint16, snapLen uint32, name string) {
	payload := make([]byte, 8)
	b.order.PutUint16(payload[0:2], linkType)
	b.order.PutUint32(payload[4:8], snapLen)
	if name != "" {
		opt := []byte{2, 0, byte(len(name) + 1), 0}
		opt = append(opt, []byte(name)...)
		opt = append(opt, 0)
		for len(opt)%4 != 0 {
			opt = append(opt, 0)
		}
		payload = append(payload, opt...)
	}
	b.block(TypeIDB, payload)
}

func (b *builder) epb(iface int, ts uint64, frame []byte, orig uint32) {
	payload := make([]byte, 20)
	b.order.PutUint32(payload[0:4], uint32(iface))
	b.order.PutUint32(payload[4:8], uint32(ts>>32))
	b.order.PutUint32(payload[8:12], uint32(ts))
	b.order.PutUint32(payload[12:16], uint32(len(frame)))
	b.order.PutUint32(payload[16:20], orig)
	payload = append(payload, frame...)
	for len(payload)%4 != 0 {
		payload = append(payload, 0)
	}
	b.block(TypeEPB, payload)
}

func (b *builder) spb(frame []byte, orig uint32) {
	padded := (len(frame) + 3) &^ 3
	payload := make([]byte, 4+padded)
	b.order.PutUint32(payload[0:4], orig)
	copy(payload[4:], frame)
	b.block(TypeSPB, payload)
}

func validFile(t *testing.T) *builder {
	t.Helper()
	b := &builder{order: binary.LittleEndian}
	b.shb()
	b.idb(1, 65535, "eth0")
	return b
}

// ipv4UDP builds a minimal Ethernet/IPv4/UDP frame.
func ipv4UDP(src, dst [4]byte, sport, dport uint16, n byte) []byte {
	f := make([]byte, 14+20+8+n)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], uint16(20+8+n))
	f[23] = 17
	copy(f[26:30], src[:])
	copy(f[30:34], dst[:])
	binary.BigEndian.PutUint16(f[34:36], sport)
	binary.BigEndian.PutUint16(f[36:38], dport)
	binary.BigEndian.PutUint16(f[38:40], uint16(8+n))
	return f
}

func TestRejectsLegacyPcap(t *testing.T) {
	for _, magic := range [][]byte{
		{0xd4, 0xc3, 0xb2, 0xa1},
		{0xa1, 0xb2, 0xc3, 0xd4},
		{0x4d, 0x3c, 0xb2, 0xa1},
		{0xa1, 0xb2, 0x3c, 0x4d},
	} {
		rd := NewReader(bytes.NewReader(magic))
		_, err := rd.Next()
		if !errors.Is(err, ErrNotPcapng) && !errors.Is(err, ErrNotPcapngNano) {
			t.Fatalf("magic % x: got %v", magic, err)
		}
	}
}

func TestRejectsGarbageAndEmpty(t *testing.T) {
	if _, err := NewReader(bytes.NewReader(nil)).Next(); !errors.Is(err, ErrNotRecognized) {
		t.Fatalf("empty: got %v", err)
	}
	if _, err := NewReader(bytes.NewReader([]byte{9, 9, 9, 9, 0, 0, 0, 0})).Next(); !errors.Is(err, ErrNotRecognized) {
		t.Fatalf("garbage: got %v", err)
	}
	// A 3-byte file is neither a pcap magic nor a block header.
	_, err := NewReader(bytes.NewReader([]byte{1, 2, 3})).Next()
	if err == nil || !strings.Contains(err.Error(), "游离字节") {
		t.Fatalf("3-byte tail: got %v", err)
	}
}

func TestTruncatedBlockReported(t *testing.T) {
	b := validFile(t)
	b.epb(0, 0, []byte{1, 2, 3}, 3)
	raw := b.buf.Bytes()
	// Cut 20 bytes off the end: the final block is mid-body.
	rd := NewReader(bytes.NewReader(raw[:len(raw)-20]))
	for {
		_, err := rd.Next()
		if err == io.EOF {
			t.Fatal("expected truncation error")
		}
		if err != nil {
			if !strings.Contains(err.Error(), "截断") {
				t.Fatalf("expected human-readable truncation error, got: %v", err)
			}
			return
		}
	}
}

func TestBadTrailingLength(t *testing.T) {
	b := validFile(t)
	raw := b.buf.Bytes()
	corrupt := append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(corrupt[len(corrupt)-4:], 1234)
	rd := NewReader(bytes.NewReader(corrupt))
	var err error
	for {
		_, err = rd.Next()
		if err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "首尾长度不一致") {
		t.Fatalf("got %v", err)
	}
}

func TestReadsEPBAndSPB(t *testing.T) {
	b := validFile(t)
	frame := []byte{0xde, 0xad, 1, 2, 3, 4, 5, 6, 0x08, 0x00}
	b.epb(0, 1_000_000, frame, 100)
	b.spb(frame, 10)
	rd := NewReader(bytes.NewReader(b.buf.Bytes()))

	var epb, spb *Packet
	for {
		blk, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch blk.Type {
		case TypeEPB:
			epb, err = DecodeEPB(blk)
			if err != nil {
				t.Fatal(err)
			}
		case TypeSPB:
			spb, err = DecodeSPB(blk)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if epb == nil || spb == nil {
		t.Fatal("missing packet block")
	}
	if !epb.Truncated || epb.Captured != 10 || epb.Original != 100 {
		t.Fatalf("EPB truncation flags wrong: %+v", epb)
	}
	if spb.EPB || spb.Captured != 10 || spb.Truncated {
		t.Fatalf("SPB decode wrong: %+v", spb)
	}
}

func TestBigEndianSection(t *testing.T) {
	b := &builder{order: binary.BigEndian}
	b.shb()
	b.idb(1, 262144, "")
	b.epb(0, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0x08, 0x00}, 10)

	rd := NewReader(bytes.NewReader(b.buf.Bytes()))
	blk, err := rd.Next() // SHB
	if err != nil {
		t.Fatal(err)
	}
	if blk.Order != binary.BigEndian {
		t.Fatal("expected big-endian order")
	}
	if _, err := rd.Next(); err != nil { // IDB
		t.Fatal(err)
	}
	epbBlock, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeEPB(epbBlock)
	if err != nil || p.Captured != 10 || p.Original != 10 {
		t.Fatalf("BE decode: %+v, %v", p, err)
	}
}

func TestFilterFiveTuple(t *testing.T) {
	udp := ipv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 53, 4)
	icmpFrame := make([]byte, 14+20)
	binary.BigEndian.PutUint16(icmpFrame[12:14], 0x0800)
	icmpFrame[14] = 0x45
	icmpFrame[23] = 1

	mustMatch := func(c *Criteria, data []byte, want bool) {
		t.Helper()
		if got := c.Match(data, 1); got != want {
			t.Fatalf("match got %v want %v", got, want)
		}
	}

	mustMatch(&Criteria{}, udp, true)
	mustMatch(&Criteria{HasEth: true, EtherType: 0x0806}, udp, false)
	mustMatch(&Criteria{HasEth: true, EtherType: 0x0800}, udp, true)
	mustMatch(&Criteria{SrcIP: netip.MustParseAddr("10.0.0.1")}, udp, true)
	mustMatch(&Criteria{SrcIP: netip.MustParseAddr("9.9.9.9")}, udp, false)
	mustMatch(&Criteria{HasProto: true, IPProto: 17}, udp, true)
	mustMatch(&Criteria{HasProto: true, IPProto: 1}, udp, false)
	mustMatch(&Criteria{HasProto: true, IPProto: 1}, icmpFrame, true)
	mustMatch(&Criteria{HasPort: true, SrcPort: 1234}, udp, true)
	mustMatch(&Criteria{HasPort: true, DstPort: 53}, udp, true)
	mustMatch(&Criteria{HasPort: true, SrcPort: 53, DstPort: 1234}, udp, false)
	// Both ports pinned: must match exact direction pair.
	mustMatch(&Criteria{HasPort: true, SrcPort: 1234, DstPort: 53}, udp, true)
	mustMatch(&Criteria{HasPort: true, SrcPort: 53, DstPort: 53}, udp, false)
	mustMatch(&Criteria{HasPort: true, DstPort: 1234}, udp, false)
	mustMatch(&Criteria{HasEth: true, EtherType: 0x0800}, udp[:10], false)
	// Non-Ethernet link type can never match L3 criteria.
	nonEth := &Criteria{HasProto: true, IPProto: 17}
	if nonEth.Match(udp, 12) {
		t.Fatal("non-Ethernet linktype should not match")
	}
}

func TestIllegalBlockLength(t *testing.T) {
	b := validFile(t)
	raw := b.buf.Bytes()
	// Append a block header claiming total length 7.
	bad := make([]byte, 8)
	binary.LittleEndian.PutUint32(bad[0:4], 42)
	binary.LittleEndian.PutUint32(bad[4:8], 7)
	rd := NewReader(bytes.NewReader(append(raw, bad...)))
	var err error
	for {
		_, err = rd.Next()
		if err != nil {
			break
		}
	}
	if !strings.Contains(err.Error(), "非法块长度") {
		t.Fatalf("got %v", err)
	}
}
