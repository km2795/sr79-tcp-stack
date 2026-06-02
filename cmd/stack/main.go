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
		fmt.Println("Failed to open TAP device. Exiting...")
		return
	}

	defer tap.Close()

	logger.Log(logger.INFO, fmt.Sprintf("TAP Interface (%s) Setup Successfully", tap.Name))

	var _err error

	// Initialize the Interface.
	_err = exec.Command("ip", "link", "set", tap.Name, "up").Run()
	if _err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Setup Error: %v", _err))
		fmt.Println("Error Initializing TAP device. Exiting...")
		return
	}

	// Assign the Initialized Interface an IP.
	_err = exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tap.Name).Run()
	if _err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Setup Error: %v", _err))
		fmt.Println("Error Setting up TAP Device. Exiting...")
		return
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
		// IPv4 datagrams.
		case uint16(ethernet.FrameIPv4):
			packet := ip.ParsePacketIPv4(frame.Payload)

			if packet == nil {
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

		case uint16(ethernet.FrameIPv6):
			packet := ip.ParsePacketIPv6(frame.Payload)
			if packet == nil {
				continue
			}

			fmt.Printf("\n--- Packet (%d bytes) ---\n", packet.PayloadLength)
			fmt.Printf("Type: %d\n", packet.Version)
			fmt.Printf("Source IP: %s\n", packet.Source.String())
			fmt.Printf("Destination IP: %s\n", packet.Destination.String())
			fmt.Printf("Payload: \n%s\n", hex.Dump(packet.Payload))

		case uint16(ethernet.FrameARP):
			fmt.Println(" -- ARP --")

		default:
			fmt.Printf(" unknown EtherType 0x%04x\n", frame.Type)
		}

	}

	logger.StopLogger()
}
