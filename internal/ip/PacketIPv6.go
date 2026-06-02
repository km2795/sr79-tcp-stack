package ip

import (
	"encoding/binary"
	"net/netip"
)

type PacketIPv6 struct {
	Version       uint8      // (4): Format of the Internet Header
	TrafficClass  uint8      // (8): bits
	FlowLabel     uint32     // (20): bits (packed into 32)
	PayloadLength uint16     // (16): bits
	NextHeader    uint8      // (8): bits (protocol or extension header type)
	HopLimit      uint8      // (8): bits (replaces TTL)
	Source        netip.Addr // (128): bits
	Destination   netip.Addr // (128): bits
	Payload       []byte
}

func ParsePacketIPv6(data []byte) *PacketIPv6 {
	if len(data) < 40 {
		return nil // Invalid IPv6 packet
	}

	packet := &PacketIPv6{
		Version:       data[0] >> 4,
		TrafficClass:  ((data[0] & 0x0F) << 4) | (data[1] >> 4),
		FlowLabel:     binary.BigEndian.Uint32(data[1:5]) & 0x000FFFFF,
		PayloadLength: binary.BigEndian.Uint16(data[4:6]),      // Note: bytes 4-5, not 6-8
		NextHeader:    data[6],                                 // Byte 6, not 8
		HopLimit:      data[7],                                 // Byte 7, not 9
		Source:        netip.AddrFrom16([16]byte(data[8:24])),  // Bytes 8-23
		Destination:   netip.AddrFrom16([16]byte(data[24:40])), // Bytes 24-39
		Payload:       data[40:],                               // Start at byte 40
	}

	return packet
}
