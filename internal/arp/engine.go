package arp

import (
	"net"
	"net/netip"
	"sr79-tcp-stack/internal/ethernet"
	"sr79-tcp-stack/logger"
)

type Engine struct {
	table    *Table
	localIP  netip.Addr
	localMAC net.HardwareAddr

	// InboundChan receives raw data frames directed to ARP from the Ethernet Layer.
	InboundChan chan []byte

	// TxFunc is a function pointer back to your L2 transmission routine.
	WriteFrame func(dstMac net.HardwareAddr, ethType uint16, payload []byte) error
}

func NewEngine(ip netip.Addr, mac net.HardwareAddr, writeFn func(net.HardwareAddr, uint16, []byte) error) *Engine {
	return &Engine{
		table:       NewTable(),
		localIP:     ip,
		localMAC:    mac,
		InboundChan: make(chan []byte, 1024),
		WriteFrame:  writeFn,
	}
}

// Run listens to the incoming frames from InboundChan,
// parses them using ParsePacketARP and decides whether to
// send an immediate ARP reply back onto the wire or execute
// a cache update.
func (e *Engine) Run() {
	var packet PacketARP

	for frame := range e.InboundChan {
		if ParsePacketARP(frame, &packet) != nil {
			switch packet.Operation {
			// On request.
			case 1:
				if e.localIP != packet.DestinationIP {
					logger.Log(logger.DEBUG, "Updating ARP Cache...")
					e.table.Update(packet.SenderIP, packet.SenderMAC, StateReachable)
					continue
				} else {
					e.table.Update(packet.SenderIP, packet.SenderMAC, StateReachable)
					replyPacket := &PacketARP{
						Operation:      OpReply,
						SenderMAC:      e.localMAC,
						SenderIP:       e.localIP,
						DestinationMAC: packet.SenderMAC,
						DestinationIP:  packet.SenderIP,
					}

					arpFrame := make([]byte, 28)
					bytesWritten := replyPacket.Marshal(arpFrame)

					if bytesWritten == 0 {
						logger.Log(logger.ERROR, "ARP Engine: Failed to serialize outbound reply frame.")
						continue
					}
					e.WriteFrame(packet.SenderMAC, uint16(ethernet.FrameARP), arpFrame)
				}

				// On reply.
			case 2:
				backlog := e.table.Update(packet.SenderIP, packet.SenderMAC, StateReachable)
				for _, flushPacket := range backlog {
					e.WriteFrame(packet.SenderMAC, uint16(ethernet.FrameIPv4), flushPacket)
				}
			}
		}
	}
}

// StartJanitor is a background ticker that handles state machine
// timers - evicting expired items from the Table and managing
// request timeouts.
func (e *Engine) StartJanitor() {}
