package pcapng

import (
	"encoding/binary"
	"fmt"
)

const (
	TypeSHB uint32 = 0x0A0D0D0A // Section Header Block
	TypeIDB uint32 = 0x00000001 // Interface Description Block
	TypeSPB uint32 = 0x00000003 // Simple Packet Block
	TypeEPB uint32 = 0x00000006 // Enhanced Packet Block
)

// MaxBlockLen caps how large a single block may be. The pcapng spec does
// not impose a hard limit, but a sane cap protects against corrupt files
// whose block-length fields point at multi-gigabyte blocks.
const MaxBlockLen = 64 * 1024 * 1024

// Block is a single pcapng block read from the stream. Payload holds the
// bytes between the block header and the trailing total-length field.
type Block struct {
	Type       uint32
	Total      uint32
	Payload    []byte
	Offset     int64 // file offset where the block starts
	Order      binary.ByteOrder
	BlockIndex int // 0-based block number within the file
}

// Interface describes one Interface Description Block.
type Interface struct {
	Index      int
	LinkType   uint16
	SnapLen    uint32
	Name       string
	Resolution byte // if_tsresol option value (default 6 = microseconds)
}

// Packet is one decoded Enhanced Packet Block or Simple Packet Block.
type Packet struct {
	Index      int // 1-based packet number within the file
	Interface  int
	EPB        bool
	TSHigh     uint32
	TSLow      uint32
	Captured   uint32
	Original   uint32
	Data       []byte
	Truncated  bool // captured length smaller than on-the-wire length
	BlockIndex int  // 0-based block number of this packet
}

// DecodeIDB parses an Interface Description Block payload.
func DecodeIDB(b *Block) (*Interface, error) {
	if len(b.Payload) < 8 {
		return nil, fmt.Errorf("IDB 块体只有 %d 字节（至少需要 8）", len(b.Payload))
	}
	o := b.Order
	iface := &Interface{
		LinkType:   o.Uint16(b.Payload[0:2]),
		SnapLen:    o.Uint32(b.Payload[4:8]),
		Resolution: 6,
	}
	if err := parseOptions(b.Payload[8:], o, func(code uint16, value []byte) {
		switch code {
		case 2: // if_name
			if n := clen(value); n > 0 {
				iface.Name = string(value[:n])
			}
		case 9: // if_tsresol
			if len(value) >= 1 {
				iface.Resolution = value[0]
			}
		}
	}); err != nil {
		return nil, err
	}
	return iface, nil
}

// DecodeEPB parses an Enhanced Packet Block payload.
func DecodeEPB(b *Block) (*Packet, error) {
	if len(b.Payload) < 20 {
		return nil, fmt.Errorf("EPB 块体只有 %d 字节（至少需要 20）", len(b.Payload))
	}
	o := b.Order
	ifaceID := int(o.Uint32(b.Payload[0:4]))
	tsHigh := o.Uint32(b.Payload[4:8])
	tsLow := o.Uint32(b.Payload[8:12])
	capLen := o.Uint32(b.Payload[12:16])
	origLen := o.Uint32(b.Payload[16:20])
	if capLen > uint32(len(b.Payload)-20) {
		return nil, fmt.Errorf("EPB 抓包长度 %d 超过块内可用字节 %d", capLen, len(b.Payload)-20)
	}
	return &Packet{
		EPB:       true,
		Interface: ifaceID,
		TSHigh:    tsHigh,
		TSLow:     tsLow,
		Captured:  capLen,
		Original:  origLen,
		Data:      b.Payload[20 : 20+capLen],
		Truncated: capLen < origLen,
	}, nil
}

// DecodeSPB parses a Simple Packet Block payload.
func DecodeSPB(b *Block) (*Packet, error) {
	if len(b.Payload) < 4 {
		return nil, fmt.Errorf("SPB 块体只有 %d 字节（至少需要 4）", len(b.Payload))
	}
	o := b.Order
	origLen := o.Uint32(b.Payload[0:4])
	avail := uint32(len(b.Payload) - 4)
	capLen := origLen
	trunc := false
	if capLen > avail {
		capLen = avail
		trunc = true
	}
	return &Packet{
		EPB:       false,
		Interface: 0, // SPB always refers to interface 0
		Captured:  capLen,
		Original:  origLen,
		Data:      b.Payload[4 : 4+capLen],
		Truncated: trunc,
	}, nil
}

func parseOptions(body []byte, o binary.ByteOrder, handle func(code uint16, value []byte)) error {
	for len(body) >= 4 {
		code := o.Uint16(body[0:2])
		length := int(o.Uint16(body[2:4]))
		body = body[4:]
		if code == 0 {
			break // opt_endofopt
		}
		if length > len(body) {
			return fmt.Errorf("选项（code=%d）声明长度 %d 超出块体 %d 字节", code, length, len(body))
		}
		handle(code, body[:length])
		pad := (4 - length%4) % 4
		body = body[length+pad:]
	}
	return nil
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

func blockName(t uint32) string {
	switch t {
	case TypeSHB:
		return "SHB"
	case TypeIDB:
		return "IDB"
	case TypeSPB:
		return "SPB"
	case TypeEPB:
		return "EPB"
	default:
		return fmt.Sprintf("0x%08x", t)
	}
}
