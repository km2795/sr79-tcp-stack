package ip

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

type Packet struct {
	Version     uint8      // (4): Format of the Internet Header (4)
	IHL         uint8      // (4): Internet Header Length
	TOS         uint8      // (8): Quality of Service
	Length      uint16     // (16): Total length of the datagram (header + data)
	ID          uint16     // (16): For fragmentation purpose.
	Flags       uint8      // (3): Control Flags.
	FragOffset  uint16     // (13):
	TTL         uint8      // (8): When to destroy.
	Protocol    uint8      // (8): Next layer protocol.
	Checksum    uint16     // (16): For Header only, as some fields may be modified (TTL).
	Source      netip.Addr // (32): Address of the Sender.
	Destination netip.Addr // (32): Address of the Recipient.
	Payload     []byte     // Data.
}

type ProtocolType string

const (
	ProtoICMP ProtocolType = "ICMP"
	ProtoTCP  ProtocolType = "TCP"
	ProtoUDP  ProtocolType = "UDP"
)

func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("L3: Invalid datagram size (< 20): %d", len(data))
	}

	version := data[0] >> 4 // Only the first 4 bits are required.

	// Version should be 4 or 6 (else discard).
	if version != 4 && version != 6 {
		return nil, fmt.Errorf("L3: Invalid IP datagram version: %d", version)
	}

	ihl := data[0] & 0x0F     // Only the last 4 bits of the first byte of the header required.
	headerLen := int(ihl) * 4 // Size of Header Length * 4 (for each byte)

	if ihl < 5 || len(data) < headerLen {
		return nil, fmt.Errorf("L3: Invalid IHL (< 5): %d", ihl)
	}

	src := netip.AddrFrom4([4]byte(data[12:16]))
	dst := netip.AddrFrom4([4]byte(data[16:20]))

	packet := &Packet{
		Version:     version,
		IHL:         ihl,
		TOS:         data[1],
		Length:      binary.BigEndian.Uint16(data[2:4]),
		ID:          binary.BigEndian.Uint16(data[4:6]),
		Flags:       data[6] >> 5, // Only first 3 bits required.
		FragOffset:  binary.BigEndian.Uint16(data[6:8]) << 3,
		TTL:         data[8],
		Protocol:    data[9],
		Checksum:    binary.BigEndian.Uint16(data[10:12]),
		Source:      src,
		Destination: dst,
		Payload:     data[20:],
	}

	return packet, nil
}

// Checksum
// 32 bit variable is used to ensure that overflow is
// tackled properly.
func Checksum(data []byte) uint16 {
	var sum uint32

	// Combine two bytes into one 16-bit word
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Handle the odd byte if the data length is not even.
	// !! Last byte is 8 bits and we need 16 bits for addition
	// so consider the last byte as MSB in the last 2 byte block
	// and shove it in the 32 bit block for successive and final
	// addition.
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold the 32-bit sum into 16 bits (Carry-Around)
	// Keep adding the high 16 bits to the low 16 bits until no carry remains
	for sum>>16 != 0 {
		// Only the Least significant 16 bits are required.
		// Added to the 16 right shifted bits (they
		// are the carryover in the sum).
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
