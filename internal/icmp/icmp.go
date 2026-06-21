package icmp

import (
	"encoding/binary"
	"sr79-tcp-stack/logger"
)

const (
	TypeEchoReply   uint8 = 0
	TypeEchoRequest uint8 = 8
	CodeEcho        uint8 = 0
)

type PacketICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Payload  []byte
}

func ParseICMP(data []byte) *PacketICMP {
	if len(data) < 8 {
		logger.Log(logger.ERROR, "ICMP packet too short")
		return nil
	}

	if checksum(data) != 0 {
		return nil
	}

	pkt := &PacketICMP{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		ID:       binary.BigEndian.Uint16(data[4:6]),
		Seq:      binary.BigEndian.Uint16(data[6:8]),
		Payload:  data[8:],
	}

	return pkt
}

func (pkt *PacketICMP) Marshal(buf []byte) int {
	buf[0] = pkt.Type
	buf[1] = pkt.Code

	// clear checksum slot for calculation.
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint16(buf[4:6], pkt.ID)
	binary.BigEndian.PutUint16(buf[6:8], pkt.Seq)

	copy(buf[8:], pkt.Payload)

	checksum := checksum(buf[:8+len(pkt.Payload)])
	binary.BigEndian.PutUint16(buf[2:4], checksum)

	return 8 + len(pkt.Payload)
}

// Checksum handles 16-bit word accumulations over big-endian bounds.
func checksum(data []byte) uint16 {
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
