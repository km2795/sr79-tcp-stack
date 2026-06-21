package ethernet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sr79-tcp-stack/logger"
	"syscall"
)

const (
	FrameIPv4    FrameType = 0x0800
	FrameARP     FrameType = 0x0806
	FrameIPv6    FrameType = 0x086DD
	HeaderLength int       = 14
)

type FrameType uint16

type Frame struct {
	DestMac net.HardwareAddr
	SrcMac  net.HardwareAddr
	Type    FrameType
	Payload []byte
}

type Layer struct {
	tapFd    int              // File Descriptor for /dev/net/tun
	localMAC net.HardwareAddr // Stack's MAC
}

func NewLayer(fd int, localMAC net.HardwareAddr) *Layer {
	return &Layer{
		tapFd:    fd,
		localMAC: localMAC,
	}
}

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

// TransmitFrame transmits the Ethernet frame on the wire.
func (l *Layer) TransmitFrame(dstMac net.HardwareAddr, ethType uint16, payload []byte) error {
	totalLength := HeaderLength + len(payload)
	frameBuffer := make([]byte, totalLength)

	copy(frameBuffer[0:6], dstMac)      // Destination MAC
	copy(frameBuffer[6:12], l.localMAC) // Source MAC (This stack)

	// Ethernet Type (2 bytes) in Network Byte Order (Big Endian)
	frameBuffer[12] = byte(ethType >> 8)
	frameBuffer[13] = byte(ethType & 0xff)

	// At last attach the payload (after 14th Byte)
	copy(frameBuffer[HeaderLength:], payload)

	// Perform the RAW Linux system call to drop the frame (marshalled) into the kernel TAP device.
	logger.Log(logger.DEBUG, fmt.Sprintf("L2: Sending %d bytes out of TAP interface to MAC %s", totalLength, dstMac))
	_, err := syscall.Write(l.tapFd, frameBuffer)
	if err != nil {
		logger.Log(logger.ERROR, fmt.Sprintf("L2: Failed to write frame to TAP device: %v", err))
		return err
	}

	return nil
}
