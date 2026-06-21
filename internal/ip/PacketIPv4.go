package ip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sr79-tcp-stack/logger"
)

const HeaderLength = 20

type PacketIPv4 struct {
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

func ParsePacketIPv4(data []byte, packet *PacketIPv4) *PacketIPv4 {
	// Empty or truncated packets below minimal IPv4 header size
	if len(data) < 20 {
		logger.Log(logger.ERROR, "L3: Packet too short for minimal IPv4 header")
		return nil
	}

	version := data[0] >> 4
	if version != 4 {
		logger.Log(logger.ERROR, fmt.Sprintf("L3: Unsupported IP version: %d", version))
		return nil
	}

	ihl := data[0] & 0x0F     // Only the last 4 bits of the first byte of the header required.
	headerLen := int(ihl) * 4 // Size of Header Length * 4 (for each byte)

	// IHL bounds and matching wire buffer constraints
	if ihl < 5 || len(data) < headerLen {
		logger.Log(logger.ERROR, fmt.Sprintf("L3: Invalid IHL (< 5) or slice smaller than header length: %d", ihl))
		return nil
	}

	totalLength := binary.BigEndian.Uint16(data[2:4])

	// Index out-of-range panics before dynamic slicing
	if len(data) < int(totalLength) {
		logger.Log(logger.ERROR, fmt.Sprintf("L3: Truncated frame. Got %d bytes, header demands %d", len(data), totalLength))
		return nil
	}

	if int(totalLength) < headerLen {
		logger.Log(logger.ERROR, fmt.Sprintf("L3: Corrupt packet size. Total length %d less than header %d", totalLength, headerLen))
		return nil
	}

	// Checksum over the explicit header window
	if Checksum(data[0:headerLen]) != 0 {
		logger.Log(logger.ERROR, "L3: IPv4 Header Checksum mismatch")
		return nil
	}

	packet.Version = version
	packet.IHL = ihl
	packet.TOS = data[1]
	packet.Length = totalLength
	packet.ID = binary.BigEndian.Uint16(data[4:6])
	packet.Flags = data[6] >> 5 // Only first 3 bits required
	packet.FragOffset = binary.BigEndian.Uint16(data[6:8]) & 0x1FFF
	packet.TTL = data[8]
	packet.Protocol = data[9]
	packet.Checksum = binary.BigEndian.Uint16(data[10:12])
	packet.Source = netip.AddrFrom4([4]byte(data[12:16]))
	packet.Destination = netip.AddrFrom4([4]byte(data[16:20]))
	packet.Payload = data[headerLen:totalLength]

	return packet
}

// Marshal serializes the PacketIPv4 struct into a pre-allocated byte slice.
// It returns the number of bytes written.
func (pkt *PacketIPv4) Marshal(buf []byte) int {
	if len(buf) < HeaderLength {
		return 0
	}

	// 1. Pack Version (4) and IHL (5) into a single byte (0x45)
	buf[0] = (4 << 4) | 5
	buf[1] = pkt.TOS

	// 2. Pack Length, ID, and Fragmentation Flags
	binary.BigEndian.PutUint16(buf[2:4], pkt.Length)
	binary.BigEndian.PutUint16(buf[4:6], pkt.ID)

	// Combines the 3-bit flags with the 13-bit fragment offset
	flagsAndOffset := (uint16(pkt.Flags&0x07) << 13) | (pkt.FragOffset & 0x1FFF)
	binary.BigEndian.PutUint16(buf[6:8], flagsAndOffset)

	// 3. Pack TTL and Protocol
	buf[8] = pkt.TTL
	buf[9] = pkt.Protocol

	// 4. Clear Checksum slots for calculation
	binary.BigEndian.PutUint16(buf[10:12], 0)

	// 5. Fast copy the 4-byte IPv4 addresses
	// Ensure we take the 4-byte representation of the net.IP slice
	copy(buf[12:16], pkt.Source.AsSlice())
	copy(buf[16:20], pkt.Destination.AsSlice())

	// 6. Compute the Internet Checksum over ONLY the 20-byte header block
	// We reuse your excellent checksum math helper function here
	headerChecksum := Checksum(buf[:HeaderLength])
	binary.BigEndian.PutUint16(buf[10:12], headerChecksum)

	return HeaderLength
}

// Checksum handles 16-bit word accumulations over big-endian bounds.
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

// PrintPacketIPv4 prints the IPv4 packet's contents.
func PrintPacketIPv4(packet *PacketIPv4) {
	fmt.Printf("\n--- Packet (%d bytes) ---\n", packet.Length)
	fmt.Printf("Version: %d\n", packet.Version)
	fmt.Printf("Source IP: %s\n", packet.Source.String())
	fmt.Printf("Destination IP: %s\n", packet.Destination.String())
	fmt.Printf("Time to Live: %d\n", packet.TTL)
	fmt.Printf("Payload: \n%s\n", hex.Dump(packet.Payload))
}
