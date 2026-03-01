//go:build !linux

package deauth

import (
	"fmt"
	"net"
	"time"
)

// On non-Linux platforms, packet injection via AF_PACKET is not available.
// This stub allows the project to compile on macOS/Windows for development.

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type Config struct {
	Iface         string
	Packets       int
	Interval      time.Duration
	SkipBroadcast bool
	SkipMAC       net.HardwareAddr
}

type Sender struct {
	cfg Config
}

func New(cfg Config) (*Sender, error) {
	return nil, fmt.Errorf("deauth injection is only supported on Linux (requires AF_PACKET)")
}

func (s *Sender) Close() {}

func (s *Sender) Deauth(apMAC, clientMAC net.HardwareAddr) int { return 0 }
