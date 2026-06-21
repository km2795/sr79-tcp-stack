package main

import (
	"fmt"
	"net"
	"net/netip"

	"sr79-tcp-stack/internal/arp"
	"sr79-tcp-stack/internal/driver"
	"sr79-tcp-stack/internal/ethernet"
	"sr79-tcp-stack/internal/icmp"
	"sr79-tcp-stack/internal/ip"
	"sr79-tcp-stack/logger"
)

var (
	StackIP, _ = netip.ParseAddr("10.0.0.19")
	StackMAC   = net.HardwareAddr{0x02, 0x79, 0xf, 0x00, 0x00, 0x19}
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

	// Buffer for packet.
	buf := make([]byte, 2048)

	var frame ethernet.Frame
	var packetIPv4 ip.PacketIPv4
	var packetIPv6 ip.PacketIPv6

	// Setup the Ethernet Layer.
	EthernetLayer := ethernet.NewLayer(tap.GetFd(), StackMAC)

	// Initialize the ARP Engine.
	ARPEngine := arp.NewEngine(StackIP, StackMAC, EthernetLayer.TransmitFrame)

	// Start the ARP Engine goroutine.
	go ARPEngine.Run()

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

				if packetIPv4.Protocol == 1 {
					icmpPacket := icmp.ParseICMP(packetIPv4.Payload)
					if icmpPacket != nil && icmpPacket.Type == icmp.TypeEchoRequest {
						logger.Log(logger.DEBUG, "ICMP: Caught Echo Request! Forging Reply...")

						echoReply := &icmp.PacketICMP{
							Type:    icmp.TypeEchoReply,
							Code:    0,
							ID:      icmpPacket.ID,
							Seq:     icmpPacket.Seq,
							Payload: icmpPacket.Payload,
						}

						icmpBuffer := make([]byte, 8+len(icmpPacket.Payload))
						icmpBytesWritten := echoReply.Marshal(icmpBuffer)

						ipReply := &ip.PacketIPv4{
							TOS:         0,
							Length:      uint16(ip.HeaderLength + icmpBytesWritten),
							ID:          0,
							Flags:       2,
							FragOffset:  0,
							TTL:         64,
							Protocol:    1,
							Source:      StackIP,
							Destination: packetIPv4.Source,
						}

						txBuffer := make([]byte, ip.HeaderLength+icmpBytesWritten)
						ipHeaderBytes := ipReply.Marshal(txBuffer)
						copy(txBuffer[ipHeaderBytes:], icmpBuffer[:icmpBytesWritten])

						totalPacketSize := ipHeaderBytes + icmpBytesWritten
						EthernetLayer.TransmitFrame(frame.SrcMac, uint16(ethernet.FrameIPv4), txBuffer[:totalPacketSize])
					}
				}
			}

		// Parse the L3 (IPv6) datagram.
		case ethernet.FrameIPv6:
			if ip.ParsePacketIPv6(frame.Payload, &packetIPv6) != nil {
				ip.PrintPacketIPv6(&packetIPv6)
			}

			// Parse the L2.5 (ARP) datagram.
		case ethernet.FrameARP:
			arpPayload := make([]byte, len(frame.Payload))
			copy(arpPayload, frame.Payload)

			select {
			case ARPEngine.InboundChan <- arpPayload:
			default:
				// Channel buffer is completely packed. Drop the packet to preserve driver performance.
				logger.Log(logger.WARN, "Main: ARP Inbound queue full; discarding frame.")
			}
		default:
			fmt.Printf("unknown EtherType 0x%04x\n", frame.Type)
		}

	}
}
