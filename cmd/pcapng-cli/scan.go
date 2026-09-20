package main

import (
	"fmt"
	"io"
	"os"

	"pcapng/internal/pcapng"
)

// sectionVisitor reacts to block stream events. Interfaces are always
// decoded in IDB order before any callback for a later block runs.
type sectionVisitor struct {
	onSHB    func(b *pcapng.Block, st *scanState) error
	onIDB    func(b *pcapng.Block, iface *pcapng.Interface) error
	onPacket func(b *pcapng.Block, p *pcapng.Packet, st *scanState) error
	onOther  func(b *pcapng.Block) error
}

type scanState struct {
	interfaces []*pcapng.Interface
	packetNo   int
}

// scan streams every block of path without loading the file into memory.
func scan(path string, v sectionVisitor) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法打开 %q：%w", path, err)
	}
	defer f.Close()

	rd := pcapng.NewReader(f)
	st := &scanState{}
	for {
		b, err := rd.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch b.Type {
		case pcapng.TypeSHB:
			st.interfaces = nil
			if v.onSHB != nil {
				if err := v.onSHB(b, st); err != nil {
					return err
				}
			}
		case pcapng.TypeIDB:
			iface, err := pcapng.DecodeIDB(b)
			if err != nil {
				return fmt.Errorf("偏移 %d 处的 IDB 损坏：%w", b.Offset, err)
			}
			iface.Index = len(st.interfaces)
			st.interfaces = append(st.interfaces, iface)
			if v.onIDB != nil {
				if err := v.onIDB(b, iface); err != nil {
					return err
				}
			}
		case pcapng.TypeEPB:
			p, err := pcapng.DecodeEPB(b)
			if err != nil {
				return fmt.Errorf("偏移 %d 处的 EPB 损坏：%w", b.Offset, err)
			}
			st.packetNo++
			p.Index = st.packetNo
			if v.onPacket != nil {
				if err := v.onPacket(b, p, st); err != nil {
					return err
				}
			}
		case pcapng.TypeSPB:
			p, err := pcapng.DecodeSPB(b)
			if err != nil {
				return fmt.Errorf("偏移 %d 处的 SPB 损坏：%w", b.Offset, err)
			}
			st.packetNo++
			p.Index = st.packetNo
			if v.onPacket != nil {
				if err := v.onPacket(b, p, st); err != nil {
					return err
				}
			}
		default:
			if v.onOther != nil {
				if err := v.onOther(b); err != nil {
					return err
				}
			}
		}
	}
}

func (st *scanState) iface(p *pcapng.Packet) *pcapng.Interface {
	if p.Interface >= 0 && p.Interface < len(st.interfaces) {
		return st.interfaces[p.Interface]
	}
	return nil
}
