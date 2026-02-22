// Package probe tracks 802.11 probe request frames.
// When clients are deauthed they broadcast probe requests revealing
// SSIDs of previously joined networks.
package probe

import (
	"encoding/json"
	"net"
	"os"
	"sync"
)

// Entry records all SSIDs probed by a single client MAC.
type Entry struct {
	Client net.HardwareAddr
	SSIDs  []string
}

// Log is a thread-safe store of probe requests.
type Log struct {
	mu      sync.RWMutex
	entries map[string]*Entry // keyed by client MAC string
}

// NewLog creates an empty probe log.
func NewLog() *Log {
	return &Log{entries: make(map[string]*Entry)}
}

// Record adds a probe request observation.
func (l *Log) Record(client net.HardwareAddr, ssid string) {
	key := client.String()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		e = &Entry{Client: client}
		l.entries[key] = e
	}
	// Deduplicate SSIDs
	for _, s := range e.SSIDs {
		if s == ssid {
			return
		}
	}
	e.SSIDs = append(e.SSIDs, ssid)
}

// All returns a snapshot of all probe entries.
func (l *Log) All() []*Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Entry, 0, len(l.entries))
	for _, e := range l.entries {
		ssids := make([]string, len(e.SSIDs))
		copy(ssids, e.SSIDs)
		out = append(out, &Entry{Client: e.Client, SSIDs: ssids})
	}
	return out
}

// Count returns the number of unique clients seen probing.
func (l *Log) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// SaveJSON writes the probe log to a JSON file.
func (l *Log) SaveJSON(path string) error {
	entries := l.All()
	type jsonEntry struct {
		Client string   `json:"client"`
		SSIDs  []string `json:"ssids"`
	}
	out := make([]jsonEntry, len(entries))
	for i, e := range entries {
		out[i] = jsonEntry{Client: e.Client.String(), SSIDs: e.SSIDs}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
