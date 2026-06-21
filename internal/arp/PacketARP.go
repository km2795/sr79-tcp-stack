package arp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sr79-tcp-stack/logger"
)

const (
	HardwareType   = 1      // Ethernet
	ProtocolType   = 0x0800 // IPv4
	HardwareLength = 6      // MAC size 6 bytes
	ProtocolLength = 4      // IPv4 address 4 bytes
	OpRequest      = 1      // ARP request operation
	OpReply        = 2      // ARP reply operation
	Length         = 28     // Fixed size
)

type PacketARP struct {
	SenderMAC      net.HardwareAddr
	SenderIP       netip.Addr
	DestinationMAC net.HardwareAddr
	DestinationIP  netip.Addr
	Operation      uint16
}

func ParsePacketARP(data []byte, packet *PacketARP) *PacketARP {
	if len(data) < 28 {
		logger.Log(logger.ERROR, "L2: ARP packet size too short")
		return nil
	}

	hwType := binary.BigEndian.Uint16(data[0:2])
	protoType := binary.BigEndian.Uint16(data[2:4])
	hwLen := data[4]
	protoLen := data[5]

	// Verify the hardware and protocol type and length.
	if hwType != HardwareType || protoType != ProtocolType || hwLen != HardwareLength || protoLen != ProtocolLength {
		logger.Log(logger.ERROR, "Invalid ARP packet (hardware info or protocol info)")
		return nil
	}

	// Request or reply.
	packet.Operation = binary.BigEndian.Uint16(data[6:8])

	// Check for previous allocation.
	if len(packet.SenderMAC) != 6 {
		packet.SenderMAC = make(net.HardwareAddr, 6)
	}

	if len(packet.DestinationMAC) != 6 {
		packet.DestinationMAC = make(net.HardwareAddr, 6)
	}

	// Fast copy.
	copy(packet.SenderMAC, data[8:14])
	copy(packet.DestinationMAC, data[18:24])

	packet.SenderIP = netip.AddrFrom4(*(*[4]byte)(data[14:18]))
	packet.DestinationIP = netip.AddrFrom4(*(*[4]byte)(data[24:28]))

	return packet
}

// Marshal serializes the PacketARP struct directly into a pre-allocated byte slice.
// It returns the number of bytes written or an error if the slice is too small.
func (packet *PacketARP) Marshal(data []byte) int {
	// Check if the buffer passed is at least the standard size.
	if len(data) < Length {
		logger.Log(logger.ERROR, "L2: Buffer too small for marshalling")
		return 0
	}

	// Pack the fixed headers.
	binary.BigEndian.PutUint16(data[0:2], HardwareType)
	binary.BigEndian.PutUint16(data[2:4], ProtocolType)
	data[4] = HardwareLength
	data[5] = ProtocolLength

	// Pack the dynamic field.
	binary.BigEndian.PutUint16(data[6:8], packet.Operation)

	// Fast copy the addressing fields.
	copy(data[8:14], packet.SenderMAC)
	copy(data[14:18], packet.SenderIP.AsSlice())
	copy(data[18:24], packet.DestinationMAC)
	copy(data[24:28], packet.DestinationIP.AsSlice())

	return Length
}
