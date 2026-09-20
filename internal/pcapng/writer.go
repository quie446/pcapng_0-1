package pcapng

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// SectionWriter emits one well-formed pcapng section: the original SHB is
// copied verbatim, then all IDBs of the section, then matched packets that
// were spooled to a temporary file. This preserves the source byte order
// and guarantees interfaces precede the packets referencing them.
type SectionWriter struct {
	out    io.Writer
	shb    []byte
	idbs   [][]byte
	spool  *os.File
	order  binary.ByteOrder
	packet int
}

// NewSectionWriter starts a new section with the given SHB raw block.
func NewSectionWriter(out io.Writer, shb *Block) (*SectionWriter, error) {
	f, err := os.CreateTemp("", "pcapng-filter-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("无法创建临时假脱机文件：%w", err)
	}
	return &SectionWriter{
		out:   out,
		shb:   rawBlock(shb),
		spool: f,
		order: shb.Order,
	}, nil
}

// AddIDB remembers an Interface Description Block (must be called in order).
func (s *SectionWriter) AddIDB(b *Block) error {
	cp := make([]byte, len(rawBlock(b)))
	copy(cp, rawBlock(b))
	s.idbs = append(s.idbs, cp)
	return nil
}

// AddPacket appends a matched packet block to the section spool.
func (s *SectionWriter) AddPacket(b *Block) error {
	if _, err := s.spool.Write(rawBlock(b)); err != nil {
		return fmt.Errorf("写入临时假脱机文件失败：%w", err)
	}
	s.packet++
	return nil
}

// Finish flushes SHB + IDBs + spooled packets to the output and cleans up.
func (s *SectionWriter) Finish() (int, error) {
	defer os.Remove(s.spool.Name())
	defer s.spool.Close()

	if _, err := s.out.Write(s.shb); err != nil {
		return 0, err
	}
	for _, idb := range s.idbs {
		if _, err := s.out.Write(idb); err != nil {
			return 0, err
		}
	}
	if _, err := s.spool.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	if _, err := io.Copy(s.out, s.spool); err != nil {
		return 0, err
	}
	return s.packet, nil
}

// Abort removes the temporary spool without writing the section.
func (s *SectionWriter) Abort() {
	if s == nil || s.spool == nil {
		return
	}
	name := s.spool.Name()
	s.spool.Close()
	os.Remove(name)
	s.spool = nil
}

func rawBlock(b *Block) []byte {
	out := make([]byte, 12+len(b.Payload))
	b.Order.PutUint32(out[0:4], b.Type)
	b.Order.PutUint32(out[4:8], b.Total)
	copy(out[8:], b.Payload)
	b.Order.PutUint32(out[8+len(b.Payload):], b.Total)
	return out
}
