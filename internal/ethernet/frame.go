package ethernet

import (
	"encoding/binary"
	"fmt"
	"net"
)

type Frame struct {
	DestMac net.HardwareAddr
	SrcMac  net.HardwareAddr
	Type    uint16
	Payload []byte
}

type FrameType uint16

const (
	FrameIPv4 FrameType = 0x0800
	FrameARP  FrameType = 0x0806
	FrameIPv6 FrameType = 0x086dd
)

func ParseFrame(data []byte) (*Frame, error) {
	frameLen := len(data)

	// If the length of the frame is less than 14, discard it.
	if frameLen < 14 {
		return nil, fmt.Errorf("L2: Invalid frame header size (< 14): %d", frameLen)
	}

	frame := &Frame{
		DestMac: net.HardwareAddr(data[0:6]),
		SrcMac:  net.HardwareAddr(data[6:12]),
		Type:    binary.BigEndian.Uint16(data[12:14]),
		Payload: data[14:],
	}

	return frame, nil
}
