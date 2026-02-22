package target

import (
	"net"
	"sync"
)

// AP represents a discovered access point and its associated clients.
type AP struct {
	BSSID   net.HardwareAddr
	SSID    string
	Channel int
	Clients []net.HardwareAddr
	Deauths int
}

// Table is a thread-safe store of discovered APs and their clients.
type Table struct {
	mu  sync.RWMutex
	APs map[string]*AP
	Max int // 0 = unlimited
}

// NewTable creates an empty target table.
func NewTable(max int) *Table {
	return &Table{
		APs: make(map[string]*AP),
		Max: max,
	}
}

// AddAP adds or updates an access point entry.
func (t *Table) AddAP(bssid net.HardwareAddr, ssid string, channel int) {
	key := bssid.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.APs[key]; !ok {
		t.APs[key] = &AP{
			BSSID:   bssid,
			SSID:    ssid,
			Channel: channel,
		}
	}
}

// AddClient associates a client MAC with an AP BSSID.
func (t *Table) AddClient(bssid, client net.HardwareAddr) {
	key := bssid.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	ap, ok := t.APs[key]
	if !ok {
		return
	}
	// Deduplicate
	clientKey := client.String()
	for _, c := range ap.Clients {
		if c.String() == clientKey {
			return
		}
	}
	ap.Clients = append(ap.Clients, client)
}

// IncrDeauths increments the deauth counter for an AP.
func (t *Table) IncrDeauths(bssid net.HardwareAddr) {
	key := bssid.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	if ap, ok := t.APs[key]; ok {
		ap.Deauths++
	}
}

// All returns a snapshot copy of all APs (safe to range outside lock).
func (t *Table) All() []*AP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*AP, 0, len(t.APs))
	for _, ap := range t.APs {
		clients := make([]net.HardwareAddr, len(ap.Clients))
		copy(clients, ap.Clients)
		out = append(out, &AP{
			BSSID:   ap.BSSID,
			SSID:    ap.SSID,
			Channel: ap.Channel,
			Clients: clients,
			Deauths: ap.Deauths,
		})
	}
	return out
}

// Count returns the number of tracked APs.
func (t *Table) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.APs)
}

// TotalDeauths returns the sum of all deauth packets sent.
func (t *Table) TotalDeauths() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := 0
	for _, ap := range t.APs {
		total += ap.Deauths
	}
	return total
}

// CheckAndClear clears the table if Max is set and reached.
// Returns true if cleared.
func (t *Table) CheckAndClear() bool {
	if t.Max == 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.APs) >= t.Max {
		t.APs = make(map[string]*AP)
		return true
	}
	return false
}
