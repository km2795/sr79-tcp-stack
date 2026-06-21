package arp

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"sr79-tcp-stack/logger"
)

type State uint8

const (
	StateIncomplete State = iota // Request state, waiting for reply
	StateReachable               // MAC is validated, active traffic allowed
	StateStale                   // Old entry, still usable but needs verification.
	QueueLength     int   = 32   // Maximum number packets allowed in the queue.
)

// Single Entry in the Cache.
type Entry struct {
	MAC       net.HardwareAddr
	State     State
	UpdatedAt time.Time
	// TxQueue stores raw outbound IP packets waiting for this MAC to resolve.
	TxQueue [][]byte
}

// The ARP table.
type Table struct {
	mu    sync.RWMutex
	cache map[[4]byte]*Entry
}

func NewTable() *Table {
	return &Table{
		cache: make(map[[4]byte]*Entry),
	}
}

// Lookup returns the MAC entry for an IP.
func (t *Table) Lookup(ip netip.Addr) (net.HardwareAddr, State, bool) {
	ipKey := ip.As4()

	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, exists := t.cache[ipKey]
	if !exists {
		return nil, 0, false
	}

	return entry.MAC, entry.State, true
}

// Update modifies the current state of a table entry.
func (t *Table) Update(ip netip.Addr, mac net.HardwareAddr, state State) [][]byte {
	ipKey := ip.As4()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.cache[ipKey]

	// Case A: Completely new neighbor discovered
	if !exists {
		t.cache[ipKey] = &Entry{
			MAC:       append(net.HardwareAddr(nil), mac...), // Deep copy the MAC
			State:     state,
			UpdatedAt: time.Now(),
			TxQueue:   nil,
		}
		return nil
	}

	// Case B: Updating an existing neighbor
	entry.MAC = append(entry.MAC[:0], mac...) // Overwrite memory in-place
	entry.State = state
	entry.UpdatedAt = time.Now()

	// If there are packets waiting for this MAC, drain them out to be flushed
	if len(entry.TxQueue) > 0 {
		queuedPackets := entry.TxQueue
		entry.TxQueue = nil // Free up queue memory inside the table
		return queuedPackets
	}

	return nil
}

// QueuePacket used when the state is incomplete or is stale.
// Cap on the queue length is ensured.
func (t *Table) QueuePacket(ip net.IP, packetData []byte) {
	var ipKey [4]byte
	copy(ipKey[:], ip.To4())

	// Lock the Table for exclusive write.
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if an entry for the IP key exists.
	entry, exists := t.cache[ipKey]
	if !exists {
		// Create an incomplete entry placeholder if it doesn't exist yet
		entry = &Entry{
			State:     StateIncomplete,
			UpdatedAt: time.Now(),
			TxQueue:   make([][]byte, 0, 4),
		}
		t.cache[ipKey] = entry
	}

	// Cap the queue depth to prevent memory exhaustion attacks
	if len(entry.TxQueue) >= QueueLength {
		logger.Log(logger.ALERT, "ARP: TxQueue full, dropping oldest pending packet")
		entry.TxQueue = entry.TxQueue[1:] // Drop the oldest packet
	}

	// Store a copy of the packet payload securely
	packetCopy := make([]byte, len(packetData))
	copy(packetCopy, packetData)
	entry.TxQueue = append(entry.TxQueue, packetCopy)
}
