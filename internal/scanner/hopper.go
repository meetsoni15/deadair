package scanner

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Hopper manages sequential channel-hopping on a wireless interface.
type Hopper struct {
	Iface    string
	MaxChan  int // 11 (N. America) or 13 (world)
	LockedCh int // 0 = hop, >0 = locked to this channel

	Current int
	done    chan struct{}
	Ready   chan struct{} // closed after first full sweep
}

// NewHopper creates a Hopper. Set locked=0 to hop, or a channel number to lock.
func NewHopper(iface string, maxChan, locked int) *Hopper {
	return &Hopper{
		Iface:    iface,
		MaxChan:  maxChan,
		LockedCh: locked,
		done:     make(chan struct{}),
		Ready:    make(chan struct{}),
	}
}

// Run starts the hopping loop. Call in a goroutine.
// advanceCh receives a signal when deauth for current channel is done (for fast hopping).
func (h *Hopper) Run(advanceCh <-chan struct{}) {
	defer close(h.Ready)

	if h.LockedCh > 0 {
		// Locked — set once and stay
		_ = h.setChannel(h.LockedCh)
		h.Current = h.LockedCh
		// Signal ready immediately, then block until stopped
		select {
		case <-h.done:
		}
		return
	}

	firstPass := true

	for {
		for ch := 1; ch <= h.MaxChan; ch++ {
			select {
			case <-h.done:
				return
			default:
			}

			if err := h.setChannel(ch); err == nil {
				h.Current = ch
			}

			if firstPass {
				// Slow first pass: 1 second per channel to discover targets
				select {
				case <-time.After(1 * time.Second):
				case <-h.done:
					return
				}
			} else {
				// Fast pass: wait for deauth signal or a short timeout
				select {
				case <-advanceCh:
				case <-time.After(200 * time.Millisecond):
				case <-h.done:
					return
				}
			}
		}

		if firstPass {
			firstPass = false
			close(h.Ready) // Signal that first pass is done — re-close guard needed
		}
	}
}

// Stop stops the hopper goroutine.
func (h *Hopper) Stop() {
	close(h.done)
}

// setChannel sets the wireless interface to the given channel.
func (h *Hopper) setChannel(ch int) error {
	chStr := strconv.Itoa(ch)
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("iw", "dev", h.Iface, "set", "channel", chStr).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iw set channel %d: %s", ch, strings.TrimSpace(string(out)))
		}
		return nil
	case "darwin":
		// macOS: airport utility (limited, may need full path)
		airport := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
		out, err := exec.Command(airport, h.Iface, "-c"+chStr).CombinedOutput()
		if err != nil {
			return fmt.Errorf("airport set channel %d: %s", ch, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return fmt.Errorf("channel hopping not supported on %s", runtime.GOOS)
	}
}
