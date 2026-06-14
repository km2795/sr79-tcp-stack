package main

import (
	"encoding/hex"
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
		// Parse the L3 datagram.
		case ethernet.FrameIPv4:
			packet := ip.ParsePacketIPv4(frame.Payload, &packetIPv4)

			if packet == nil {
				continue
			}

			fmt.Printf("\n--- Packet (%d bytes) ---\n", packet.Length)
			fmt.Printf("Type: %d\n", packet.Version)
			fmt.Printf("Source IP: %s\n", packet.Source.String())
			fmt.Printf("Destination IP: %s\n", packet.Destination.String())
			fmt.Printf("Time to Live: %d\n", packet.TTL)
			fmt.Printf("Payload: \n%s\n", hex.Dump(packet.Payload))

		case ethernet.FrameIPv6:
			packet := ip.ParsePacketIPv6(frame.Payload, &packetIPv6)
			if packet == nil {
				continue
			}

			fmt.Printf("\n--- Packet (%d bytes) ---\n", packet.PayloadLength)
			fmt.Printf("Type: %d\n", packet.Version)
			fmt.Printf("Source IP: %s\n", packet.Source.String())
			fmt.Printf("Destination IP: %s\n", packet.Destination.String())
			fmt.Printf("Payload: \n%s\n", hex.Dump(packet.Payload))

		case ethernet.FrameARP:
			fmt.Println(" -- ARP --")

		default:
			fmt.Printf(" unknown EtherType 0x%04x\n", frame.Type)
		}

	}
}
