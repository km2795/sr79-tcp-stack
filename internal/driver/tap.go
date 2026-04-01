package driver

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
	"sr79-tcp-stack/logger"
)

// Interface Flags (NIC settings).
const (
	IFFTAP    = 0x0002 // TAP driver.
	IFFNOPI   = 0x1000 // No Packet Information required.
	TUNSETIFF = 0x400454ca
)

// Interface properties.
type ifReq struct {
	Name  [16]byte // Name of the virtual NIC.
	Flags uint16   // Flags for the virtual NIC.
	_     [22]byte // Padding to match kernel's 40 bytes requirement.
}

// TAP
type TAP struct {
	file *os.File
	Name string
}

func OpenTAP(name string) (*TAP, error) {
	// Open a new virtual tunnel.
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		logger.Log(logger.ERROR, fmt.Sprintf("Unable to open TAP driver: %v", err))
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	// Pass name and flags to the tunnel.
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = IFFTAP | IFFNOPI

	// Call kernel to configure the TAP device.
	// unsafe.Pointer() to prevent GO's Garbage Collector from
	// moving it.
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		TUNSETIFF,
		uintptr(unsafe.Pointer(&req)),
	)

	if errno != 0 {
		f.Close()
		logger.Log(logger.ERROR, fmt.Sprintf("Unable to set tunnel: %v", errno))
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	// Convert null-terminated string to clean GO string.
	// "tap0\x00\x00\x00" (kernel returned string) -> "tap0"
	ifName := string(bytes.Trim(req.Name[:], "\x00"))

	return &TAP{file: f, Name: ifName}, nil
}

func (t *TAP) Read(buf []byte) (int, error) {
	return t.file.Read(buf)
}

func (t *TAP) Write(buf []byte) (int, error) {
	return t.file.Write(buf)
}

func (t *TAP) Close() error {
	return t.file.Close()
}
