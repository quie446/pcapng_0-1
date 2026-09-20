package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	BlockTypeSHB = 0x0A0D0D0A
	BlockTypeIDB = 0x00000001
	BlockTypeSPB = 0x00000003
	BlockTypeEPB = 0x00000006

	byteOrderMagic = 0x1A2B3C4D
)

// classic pcap magic byte patterns (as they appear on disk)
var classicPcapMagics = [][]byte{
	{0xa1, 0xb2, 0xc3, 0xd4}, // microsecond, big-endian writer
	{0xd4, 0xc3, 0xb2, 0xa1}, // microsecond, little-endian writer
	{0xa1, 0xb2, 0x3c, 0x4d}, // nanosecond, big-endian writer
	{0x4d, 0x3c, 0xb2, 0xa1}, // nanosecond, little-endian writer
}

type Interface struct {
	LinkType uint16
	SnapLen  uint32
	Name     string
	tsMult   float64 // multiply raw timestamp by this to get seconds
}

type Block struct {
	Type   uint32
	Raw    []byte // full block: header + body + trailing length
	Body   []byte // block body (between 8-byte header and 4-byte trailer)
	Offset int64  // file offset of the block start
}

type Packet struct {
	Index     int // 1-based packet index in file
	IfaceID   uint32
	HasIface  bool // false for SPB (implicitly interface 0)
	Timestamp float64
	HasTS     bool
	CapLen    uint32
	OrigLen   uint32
	Data      []byte // captured bytes (CapLen long)
	Raw       []byte // raw block bytes, for write-out
}

type Reader struct {
	r        *bufio.Reader
	bo       binary.ByteOrder
	offset   int64
	ifaces   []*Interface
	seenSHB  bool
	pktIndex int
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 1<<20), bo: binary.LittleEndian}
}

func (rd *Reader) Interfaces() []*Interface { return rd.ifaces }

// NextBlock reads the next block, validating lengths. Returns io.EOF at clean end.
func (rd *Reader) NextBlock() (*Block, error) {
	start := rd.offset
	hdr := make([]byte, 8)
	n, err := io.ReadFull(rd.r, hdr)
	if err != nil {
		if err == io.EOF && n == 0 {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("offset %d: truncated block header (got %d of 8 bytes): file ends mid-block", start, n)
	}
	rd.offset += 8

	if !rd.seenSHB {
		for _, m := range classicPcapMagics {
			if string(hdr[:4]) == string(m) {
				return nil, fmt.Errorf("not a pcapng file: classic pcap magic %x detected (this tool only reads pcapng)", hdr[:4])
			}
		}
	}

	blockType := rd.bo.Uint32(hdr[:4])
	var totalLen uint32
	var bodyHead []byte // already-read bytes that belong to the body (SHB byte-order magic)

	if blockType == BlockTypeSHB {
		bom := make([]byte, 4)
		if _, err := io.ReadFull(rd.r, bom); err != nil {
			return nil, fmt.Errorf("offset %d: truncated Section Header Block (missing byte-order magic)", start)
		}
		rd.offset += 4
		switch binary.LittleEndian.Uint32(bom) {
		case byteOrderMagic:
			rd.bo = binary.LittleEndian
		case 0x4D3C2B1A:
			rd.bo = binary.BigEndian
		default:
			return nil, fmt.Errorf("offset %d: invalid byte-order magic %x in Section Header Block", start, bom)
		}
		totalLen = rd.bo.Uint32(hdr[4:8])
		bodyHead = bom
		rd.seenSHB = true
		rd.ifaces = nil // new section resets interface list
	} else {
		if !rd.seenSHB {
			return nil, fmt.Errorf("offset %d: first block is not a Section Header Block (type 0x%08x); not a pcapng file", start, blockType)
		}
		totalLen = rd.bo.Uint32(hdr[4:8])
	}

	if totalLen < 12 {
		return nil, fmt.Errorf("offset %d: illegal block total length %d (minimum is 12)", start, totalLen)
	}
	if blockType == BlockTypeSHB && totalLen < 28 {
		return nil, fmt.Errorf("offset %d: illegal Section Header Block length %d (minimum is 28)", start, totalLen)
	}

	rest := make([]byte, int(totalLen)-8)
	copy(rest, bodyHead)
	if _, err := io.ReadFull(rd.r, rest[len(bodyHead):]); err != nil {
		return nil, fmt.Errorf("offset %d: truncated block (type 0x%08x, declared length %d): file ends mid-block", start, blockType, totalLen)
	}
	rd.offset += int64(totalLen) - 8

	trailer := rd.bo.Uint32(rest[len(rest)-4:])
	if trailer != totalLen {
		return nil, fmt.Errorf("offset %d: block length mismatch (header says %d, trailer says %d): corrupt file", start, totalLen, trailer)
	}

	raw := append(hdr, rest...)
	body := rest[:len(rest)-4]
	if blockType == BlockTypeSHB {
		body = body[len(bodyHead):]
	}
	return &Block{Type: blockType, Raw: raw, Body: body, Offset: start}, nil
}

// NextPacket scans blocks until the next EPB/SPB packet, updating interface
// state along the way. Returns io.EOF when no more packets.
func (rd *Reader) NextPacket() (*Packet, error) {
	for {
		blk, err := rd.NextBlock()
		if err != nil {
			return nil, err
		}
		switch blk.Type {
		case BlockTypeIDB:
			iface, err := parseIDB(rd.bo, blk.Body)
			if err != nil {
				return nil, fmt.Errorf("offset %d: %w", blk.Offset, err)
			}
			rd.ifaces = append(rd.ifaces, iface)
		case BlockTypeEPB:
			rd.pktIndex++
			pkt, err := rd.parseEPB(blk)
			if err != nil {
				return nil, err
			}
			pkt.Index = rd.pktIndex
			return pkt, nil
		case BlockTypeSPB:
			rd.pktIndex++
			pkt, err := rd.parseSPB(blk)
			if err != nil {
				return nil, err
			}
			pkt.Index = rd.pktIndex
			return pkt, nil
		}
	}
}

func parseIDB(bo binary.ByteOrder, body []byte) (*Interface, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("Interface Description Block too short (%d bytes)", len(body))
	}
	iface := &Interface{
		LinkType: bo.Uint16(body[0:2]),
		SnapLen:  bo.Uint32(body[4:8]),
		tsMult:   1e-6,
	}
	// options
	opts := body[8:]
	for len(opts) >= 4 {
		code := bo.Uint16(opts[0:2])
		l := int(bo.Uint16(opts[2:4]))
		opts = opts[4:]
		if code == 0 {
			break
		}
		if l > len(opts) {
			break // malformed option area; tolerate
		}
		val := opts[:l]
		opts = opts[pad4(l):]
		switch code {
		case 2: // if_name
			iface.Name = string(val)
		case 9: // if_tsresol
			if len(val) >= 1 {
				v := val[0]
				if v&0x80 != 0 {
					iface.tsMult = 1.0 / float64(uint64(1)<<(v&0x7f))
				} else {
					m := 1.0
					for i := 0; i < int(v); i++ {
						m *= 10
					}
					iface.tsMult = 1.0 / m
				}
			}
		}
	}
	return iface, nil
}

func (rd *Reader) parseEPB(blk *Block) (*Packet, error) {
	b := blk.Body
	if len(b) < 20 {
		return nil, fmt.Errorf("offset %d: Enhanced Packet Block too short (%d bytes)", blk.Offset, len(b))
	}
	bo := rd.bo
	ifaceID := bo.Uint32(b[0:4])
	tsHigh := bo.Uint32(b[4:8])
	tsLow := bo.Uint32(b[8:12])
	capLen := bo.Uint32(b[12:16])
	origLen := bo.Uint32(b[16:20])
	if int(capLen) > len(b)-20 {
		return nil, fmt.Errorf("offset %d: Enhanced Packet Block captured length %d exceeds block body (%d bytes)", blk.Offset, capLen, len(b)-20)
	}
	pkt := &Packet{
		IfaceID:  ifaceID,
		HasIface: true,
		HasTS:    true,
		CapLen:   capLen,
		OrigLen:  origLen,
		Data:     b[20 : 20+capLen],
		Raw:      blk.Raw,
	}
	if int(ifaceID) < len(rd.ifaces) {
		pkt.Timestamp = float64(uint64(tsHigh)<<32|uint64(tsLow)) * rd.ifaces[ifaceID].tsMult
	} else {
		pkt.Timestamp = float64(uint64(tsHigh)<<32|uint64(tsLow)) * 1e-6
	}
	return pkt, nil
}

func (rd *Reader) parseSPB(blk *Block) (*Packet, error) {
	b := blk.Body
	if len(b) < 4 {
		return nil, fmt.Errorf("offset %d: Simple Packet Block too short (%d bytes)", blk.Offset, len(b))
	}
	origLen := rd.bo.Uint32(b[0:4])
	snap := uint32(origLen)
	if len(rd.ifaces) > 0 && rd.ifaces[0].SnapLen != 0 && rd.ifaces[0].SnapLen < snap {
		snap = rd.ifaces[0].SnapLen
	}
	if int(snap) > len(b)-4 {
		snap = uint32(len(b) - 4)
	}
	return &Packet{
		IfaceID: 0,
		CapLen:  snap,
		OrigLen: origLen,
		Data:    b[4 : 4+snap],
		Raw:     blk.Raw,
	}, nil
}

func pad4(n int) int { return (n + 3) &^ 3 }
