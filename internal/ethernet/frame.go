package ethernet

import (
	"encoding/binary"
	"net"
	"sr79-tcp-stack/logger"
)

const HeaderLength = 14

type Frame struct {
	DestMac net.HardwareAddr
	SrcMac  net.HardwareAddr
	Type    FrameType
	Payload []byte
}

type FrameType uint16

const (
	FrameIPv4 FrameType = 0x0800
	FrameARP  FrameType = 0x0806
	FrameIPv6 FrameType = 0x086DD
)

func ParseFrame(data []byte, frame *Frame) *Frame {
	// If the length of the frame is less than 14, discard it.
	if len(data) < HeaderLength {
		logger.Log(logger.ERROR, "L2: Invalid frame header size (< 14)")
		return nil
	}

	// Check for previous allocation.
	if len(frame.DestMac) != 6 {
		frame.DestMac = make(net.HardwareAddr, 6)
	}

	if len(frame.SrcMac) != 6 {
		frame.SrcMac = make(net.HardwareAddr, 6)
	}

	// Copy the MACs. Prevents the
	copy(frame.DestMac, data[0:6])
	copy(frame.SrcMac, data[6:12])

	frame.Type = FrameType(binary.BigEndian.Uint16(data[12:14]))
	frame.Payload = data[14:]

	return frame
}
