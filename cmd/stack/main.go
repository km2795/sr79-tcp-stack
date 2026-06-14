package main

import (
	"fmt"

	"sr79-tcp-stack/internal/driver"
	"sr79-tcp-stack/internal/ethernet"
	"sr79-tcp-stack/internal/ip"
	"sr79-tcp-stack/logger"
)

func main() {
	logger.StartLogger()
	defer logger.StopLogger()

	// Setup the interface
	tap, err := driver.SetupTAPInterface("tap0")
	if err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Initialization Error: %v", err))
		return
	}

	// Cleanup.
	defer tap.Close()

	var frame ethernet.Frame

	// Buffer for packet.
	buf := make([]byte, 2048)
	var packetIPv4 ip.PacketIPv4
	var packetIPv6 ip.PacketIPv6

	for {
		n, err := tap.Read(buf)
		if err != nil {
			logger.Log(logger.ERROR, fmt.Sprintf("Read Error: %v", err))
			continue
		}

		// Parse the L2 frame.
		if ethernet.ParseFrame(buf[:n], &frame) == nil {
			continue
		}

		switch frame.Type {

		// Parse the L3 (IPv4) datagram.
		case ethernet.FrameIPv4:
			if ip.ParsePacketIPv4(frame.Payload, &packetIPv4) != nil {
				ip.PrintPacketIPv4(&packetIPv4)
			}

		// Parse the L3 (IPv6) datagram.
		case ethernet.FrameIPv6:
			if ip.ParsePacketIPv6(frame.Payload, &packetIPv6) != nil {
				ip.PrintPacketIPv6(&packetIPv6)
			}

		// Parse the L2 (ARP) datagram.
		case ethernet.FrameARP:
			fmt.Println("-- ARP --")

		default:
			fmt.Printf("unknown EtherType 0x%04x\n", frame.Type)
		}

	}
}
