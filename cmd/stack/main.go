package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"

	"sr79-tcp-stack/internal/driver"
	"sr79-tcp-stack/internal/ethernet"
	"sr79-tcp-stack/internal/ip"
	"sr79-tcp-stack/logger"
)

// setupTAPInterface configures the interface.
func setupTAPInterface(tapName string) (*driver.TAP, error) {
	tap, err := driver.OpenTAP(tapName)
	if err != nil {
		return nil, fmt.Errorf("failed to open TAP: %w", err)
	}

	// Initialize the Interface.
	if err := exec.Command("ip", "link", "set", tap.Name, "up").Run(); err != nil {
		tap.Close()
		return nil, fmt.Errorf("failed to bring up link: %w", err)
	}

	// Assign the Initialized Interface an IP.
	if err := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tap.Name).Run(); err != nil {
		tap.Close()
		return nil, fmt.Errorf("failed to assign IP: %w", err)
	}

	logger.Log(logger.INFO, fmt.Sprintf("TAP Interface (%s) Setup Successfully", tap.Name))
	return tap, nil
}

func main() {
	logger.StartLogger()
	defer logger.StopLogger()

	// Setup the interface
	tap, err := setupTAPInterface("tap0")
	if err != nil {
		logger.Log(logger.FATAL, fmt.Sprintf("Setup failed.: %v", err))
		fmt.Fprintf(os.Stderr, "Initialization Error: %v", err)
		return
	}

	// Cleanup.
	defer tap.Close()

	// Buffer for packet.
	buf := make([]byte, 2048)
	var packet ip.PacketIPv4

	for {
		n, err := tap.Read(buf)
		if err != nil {
			logger.Log(logger.ERROR, fmt.Sprintf("Read Error: %v", err))
			continue
		}

		frame, err := ethernet.ParseFrame(buf[:n])
		if err != nil {
			logger.Log(logger.ERROR, fmt.Sprintf("%v\n", err))
			continue
		}

		switch frame.Type {
		// IPv4 datagrams.
		case uint16(ethernet.FrameIPv4):
			packet := ip.ParsePacketIPv4(frame.Payload, &packet)

			if packet == nil {
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
}
