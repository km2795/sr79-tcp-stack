package main

import (
	"encoding/hex"
	"fmt"
	"os/exec"

	"sr79-tcp-stack/internal/driver"
	"sr79-tcp-stack/internal/ethernet"
	"sr79-tcp-stack/internal/ip"
	"sr79-tcp-stack/logger"
)

func main() {
	logger.StartLogger()
	tap, err := driver.OpenTAP("tap0")
	if err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Failed to open TAP: %v", err))
	}

	defer tap.Close()

	logger.Log(logger.INFO, fmt.Sprintf("TAP Interface (%s) Setup Successfully", tap.Name))

	var _err error

	// Initialize the Interface.
	_err = exec.Command("ip", "link", "set", tap.Name, "up").Run()
	if _err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Setup Error: %v", _err))
	}

	// Assign the Initialized Interface an IP.
	_err = exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tap.Name).Run()
	if _err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Setup Error: %v", _err))
	}

	buf := make([]byte, 1500)
	for {
		n, err := tap.Read(buf)
		if err != nil {
			logger.Log(logger.ERROR, fmt.Sprintf("Read Error: %v", err))
			continue
		}

		frame, err := ethernet.ParseFrame(buf[:n])
		if err != nil {
			logger.Log(logger.FATAL, fmt.Sprintf("%v\n", err))
			continue
		}

		switch frame.Type {
		// IPv4 and IPv6 datagrams.
		case uint16(ethernet.FrameIPv4), uint16(ethernet.FrameIPv6):
			packet, err := ip.ParsePacket(frame.Payload)
			if err != nil {
				logger.Log(logger.FATAL, fmt.Sprintf("%v\n", err))
				continue
			}

			// Skip if not true.
			if ip.Checksum(frame.Payload[0:packet.IHL*4]) != 0 {
				continue
			}

			fmt.Printf("\n--- Packet (%d bytes) ---\n", packet.Length)
			fmt.Printf("Type: %d\n", packet.Version)
			fmt.Printf("Source IP: %s\n", packet.Source.String())
			fmt.Printf("Destination IP: %s\n", packet.Destination.String())
			fmt.Printf("Time to Live: %d\n", packet.TTL)
			fmt.Printf("Payload: \n%s\n", hex.Dump(packet.Payload))

		case uint16(ethernet.FrameARP):
			fmt.Println(" -- ARP --")

		default:
			fmt.Printf(" unknown EtherType 0x%04x\n", frame.Type)
		}

	}

	logger.StopLogger()
}
