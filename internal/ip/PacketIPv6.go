package ip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

func ParsePacketIPv6(data []byte, packet *PacketIPv6) *PacketIPv6 {
	if len(data) < 40 {
		return nil // Invalid IPv6 packet
	}

	packet.Version = data[0] >> 4
	packet.TrafficClass = ((data[0] & 0x0F) << 4) | (data[1] >> 4)
	packet.FlowLabel = binary.BigEndian.Uint32(data[1:5]) & 0x000FFFFF
	packet.PayloadLength = binary.BigEndian.Uint16(data[4:6])    // Note: bytes 4-5, not 6-8
	packet.NextHeader = data[6]                                  // Byte 6, not 8
	packet.HopLimit = data[7]                                    // Byte 7, not 9
	packet.Source = netip.AddrFrom16([16]byte(data[8:24]))       // Bytes 8-23
	packet.Destination = netip.AddrFrom16([16]byte(data[24:40])) // Bytes 24-39
	packet.Payload = data[40:]                                   // Start at byte 40

	return packet
}

// PrintPacketIPv4 prints the IPv6 packet's contents.
func PrintPacketIPv6(packet *PacketIPv6) {
	fmt.Printf("\n--- Packet (%d bytes) ---\n", packet.PayloadLength)
	fmt.Printf("Type: %d\n", packet.Version)
	fmt.Printf("Source IP: %s\n", packet.Source.String())
	fmt.Printf("Destination IP: %s\n", packet.Destination.String())
	fmt.Printf("Payload: \n%s\n", hex.Dump(packet.Payload))
}
