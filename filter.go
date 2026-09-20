package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Filter is a coarse Ethernet/IPv4 5-tuple matcher. A nil/zero field means "any".
type Filter struct {
	EtherType *uint16
	SrcIP     net.IP
	DstIP     net.IP
	Proto     *uint8
	SrcPort   *uint16
	DstPort   *uint16
}

func (f *Filter) empty() bool {
	return f.EtherType == nil && f.SrcIP == nil && f.DstIP == nil &&
		f.Proto == nil && f.SrcPort == nil && f.DstPort == nil
}

// Match reports whether the packet's captured bytes pass the filter.
// Packets too short to inspect never match a constrained filter.
func (f *Filter) Match(pkt *Packet, linkType uint16) bool {
	if f.empty() {
		return true
	}
	if linkType != 1 { // only Ethernet LINKTYPE supported for field filters
		return false
	}
	d := pkt.Data
	if len(d) < 14 {
		return false
	}
	et := binary.BigEndian.Uint16(d[12:14])
	off := 14
	// unwrap up to two VLAN tags (802.1Q / 802.1ad)
	for i := 0; i < 2 && (et == 0x8100 || et == 0x88a8 || et == 0x9100); i++ {
		if len(d) < off+4 {
			return false
		}
		et = binary.BigEndian.Uint16(d[off+2 : off+4])
		off += 4
	}
	if f.EtherType != nil && et != *f.EtherType {
		return false
	}
	needsIP := f.SrcIP != nil || f.DstIP != nil || f.Proto != nil || f.SrcPort != nil || f.DstPort != nil
	if !needsIP {
		return true
	}
	if et != 0x0800 || len(d) < off+20 {
		return false
	}
	ip := d[off:]
	if ip[0]>>4 != 4 {
		return false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return false
	}
	if f.SrcIP != nil && !net.IP(ip[12:16]).Equal(f.SrcIP) {
		return false
	}
	if f.DstIP != nil && !net.IP(ip[16:20]).Equal(f.DstIP) {
		return false
	}
	proto := ip[9]
	if f.Proto != nil && proto != *f.Proto {
		return false
	}
	if f.SrcPort != nil || f.DstPort != nil {
		if proto != 6 && proto != 17 {
			return false
		}
		if len(ip) < ihl+4 {
			return false
		}
		srcPort := binary.BigEndian.Uint16(ip[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(ip[ihl+2 : ihl+4])
		if f.SrcPort != nil && srcPort != *f.SrcPort {
			return false
		}
		if f.DstPort != nil && dstPort != *f.DstPort {
			return false
		}
	}
	return true
}

func parseUint16(s string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	return uint16(v), nil
}

func parseProto(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "icmp":
		return 1, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	}
	v, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid protocol %q (use tcp/udp/icmp or a number)", s)
	}
	return uint8(v), nil
}
