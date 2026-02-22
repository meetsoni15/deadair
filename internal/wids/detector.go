// Package wids implements Wireless Intrusion Detection.
// In --wids mode deadair switches from attacking to defending:
// it monitors for abnormal deauth frame bursts and raises alerts.
package wids

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Alert represents a detected deauth attack event.
type Alert struct {
	BSSID     net.HardwareAddr
	Attacker  net.HardwareAddr // source of deauth frames
	FrameRate int              // frames per second
	At        time.Time
}

func (a Alert) String() string {
	return fmt.Sprintf("[%s] DEAUTH ATTACK on %s from %s (%d frames/s)",
		a.At.Format("15:04:05"), a.BSSID, a.Attacker, a.FrameRate)
}

// Detector monitors deauth frame rates and fires alerts above threshold.
type Detector struct {
	Threshold int           // frames/s that trigger an alert
	Window    time.Duration // sliding window for rate calc

	mu     sync.Mutex
	counts map[string]*rateCounter // keyed by "attacker→bssid"
	Alerts chan Alert
}

type rateCounter struct {
	bssid    net.HardwareAddr
	attacker net.HardwareAddr
	times    []time.Time
}

// NewDetector creates a Detector. threshold is frames/sec to trigger an alert.
func NewDetector(threshold int) *Detector {
	return &Detector{
		Threshold: threshold,
		Window:    time.Second,
		counts:    make(map[string]*rateCounter),
		Alerts:    make(chan Alert, 64),
	}
}

// Observe records a deauth frame observation.
// bssid is the target AP, attacker is the source MAC of the deauth.
func (d *Detector) Observe(bssid, attacker net.HardwareAddr) {
	key := attacker.String() + "→" + bssid.String()
	now := time.Now()
	cutoff := now.Add(-d.Window)

	d.mu.Lock()
	defer d.mu.Unlock()

	rc, ok := d.counts[key]
	if !ok {
		rc = &rateCounter{bssid: bssid, attacker: attacker}
		d.counts[key] = rc
	}

	// Append and trim old observations
	rc.times = append(rc.times, now)
	for len(rc.times) > 0 && rc.times[0].Before(cutoff) {
		rc.times = rc.times[1:]
	}

	rate := len(rc.times)
	if rate >= d.Threshold {
		select {
		case d.Alerts <- Alert{
			BSSID:     bssid,
			Attacker:  attacker,
			FrameRate: rate,
			At:        now,
		}:
		default: // don't block
		}
		// Reset counter after firing to avoid alert storm
		rc.times = nil
	}
}
