package iface

import (
	"fmt"
	"strings"

	"github.com/google/gopacket/pcap"
)

// wirelessPrefixes are common names for wireless interfaces across OSes.
var wirelessPrefixes = []string{
	"wlan", // Linux common
	"wlp",  // Linux systemd naming
	"wlx",  // Linux USB wifi
	"en",   // macOS (en0, en1 are typically wireless)
	"wi",   // BSD
	"wifi", // generic
}

// monitorSuffixes hint that an interface is already in monitor mode.
var monitorSuffixes = []string{"mon", "monitor"}

// FindBest returns the most suitable wireless interface name.
// It prefers interfaces already in monitor mode, then falls back
// to the first wireless-looking interface found.
func FindBest() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}

	var monCandidate, wifiCandidate string

	for _, dev := range devs {
		name := strings.ToLower(dev.Name)

		// Ignore bluetooth interfaces
		if strings.Contains(name, "bluetooth") || strings.Contains(name, "btmon") {
			continue
		}

		// Already in monitor mode?
		for _, suffix := range monitorSuffixes {
			if strings.HasSuffix(name, suffix) || strings.Contains(name, suffix) {
				if monCandidate == "" {
					monCandidate = dev.Name
				}
			}
		}

		// Looks like a wireless interface?
		for _, prefix := range wirelessPrefixes {
			if strings.HasPrefix(name, prefix) {
				if wifiCandidate == "" {
					wifiCandidate = dev.Name
				}
			}
		}
	}

	if monCandidate != "" {
		return monCandidate, nil
	}
	if wifiCandidate != "" {
		return wifiCandidate, nil
	}

	return "", fmt.Errorf("no wireless interface found; use -i to specify one")
}

// List returns all pcap-visible interface names.
func List() ([]string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(devs))
	for i, d := range devs {
		names[i] = d.Name
	}
	return names, nil
}
