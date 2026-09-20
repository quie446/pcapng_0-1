package pcapng

import (
	"encoding/binary"
	"net/netip"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8
	protoICMP     = 1
	protoTCP      = 6
	protoUDP      = 17
)

// Criteria is the coarse Ethernet-type / IPv4 five-tuple filter.
type Criteria struct {
	EtherType uint16
	HasEth    bool
	SrcIP     netip.Addr
	DstIP     netip.Addr
	IPProto   uint8
	HasProto  bool
	SrcPort   uint16
	DstPort   uint16
	HasPort   bool
}

// Match reports whether a captured frame satisfies every set criterion.
// Non-Ethernet frames cannot match EtherType/IPv4 criteria; an empty
// criteria matches every packet.
func (c *Criteria) Match(data []byte, linkType uint16) bool {
	if !c.HasEth && !c.HasProto && !c.SrcIP.IsValid() && !c.DstIP.IsValid() && !c.HasPort {
		return true
	}
	if linkType != 1 { // LINKTYPE_ETHERNET
		return false
	}

	eth, ethType, ok := parseEthernet(data)
	if !ok {
		return false
	}
	if c.HasEth && ethType != c.EtherType {
		return false
	}

	if !c.SrcIP.IsValid() && !c.DstIP.IsValid() && !c.HasProto && !c.HasPort {
		return true
	}
	if ethType != etherTypeIPv4 {
		return false
	}
	ip, ipProto, payload, ok := parseIPv4(eth)
	if !ok {
		return false
	}
	if c.SrcIP.IsValid() && ip.src != c.SrcIP {
		return false
	}
	if c.DstIP.IsValid() && ip.dst != c.DstIP {
		return false
	}
	if c.HasProto && ipProto != c.IPProto {
		return false
	}
	if c.HasPort {
		if ipProto != protoTCP && ipProto != protoUDP || len(payload) < 4 {
			return false
		}
		src := binary.BigEndian.Uint16(payload[0:2])
		dst := binary.BigEndian.Uint16(payload[2:4])
		if c.SrcPort != 0 && src != c.SrcPort {
			return false
		}
		if c.DstPort != 0 && dst != c.DstPort {
			return false
		}
	}
	return true
}

// parseEthernet skips up to two 802.1Q tags and returns the L3 payload.
func parseEthernet(frame []byte) (payload []byte, etherType uint16, ok bool) {
	if len(frame) < 14 {
		return nil, 0, false
	}
	t := binary.BigEndian.Uint16(frame[12:14])
	p := frame[14:]
	for i := 0; i < 2; i++ {
		if t != etherTypeVLAN && t != etherTypeQinQ {
			break
		}
		if len(p) < 4 {
			return nil, 0, false
		}
		t = binary.BigEndian.Uint16(p[2:4])
		p = p[4:]
	}
	if t <= 1500 { // 802.3 length encapsulation, not EtherType
		return nil, t, false
	}
	return p, t, true
}

type ipPair struct {
	src netip.Addr
	dst netip.Addr
}

func parseIPv4(p []byte) (ipPair, uint8, []byte, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return ipPair{}, 0, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return ipPair{}, 0, nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(p[2:4]))
	if totalLen != 0 && totalLen < ihl {
		return ipPair{}, 0, nil, false
	}
	end := len(p)
	if totalLen != 0 && totalLen < end {
		end = totalLen
	}
	src, _ := netip.AddrFromSlice(p[12:16])
	dst, _ := netip.AddrFromSlice(p[16:20])
	return ipPair{src: src, dst: dst}, p[9], p[ihl:end], true
}
