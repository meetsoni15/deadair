package iface

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

// EnableMonitor puts the given interface into monitor mode.
// On Linux it uses `iw`. On macOS it warns that injection is unsupported.
func EnableMonitor(iface string) error {
	switch runtime.GOOS {
	case "linux":
		return linuxEnableMonitor(iface)
	case "darwin":
		return fmt.Errorf("macOS: raw packet injection is blocked by the kernel; sniff-only mode. Use a Linux machine or VM for full functionality")
	default:
		return fmt.Errorf("unsupported OS %q: manually put %s into monitor mode", runtime.GOOS, iface)
	}
}

// DisableMonitor restores the interface to managed mode.
func DisableMonitor(iface string) error {
	switch runtime.GOOS {
	case "linux":
		return linuxDisableMonitor(iface)
	case "darwin":
		return nil // no-op, nothing was enabled
	default:
		return nil
	}
}

// MonitorName returns the expected monitor-mode interface name.
// If airmon-ng was used, it might be iface+"mon". If iw was used, it stays iface.
func MonitorName(iface string) string {
	if strings.HasSuffix(iface, "mon") {
		return iface
	}

	// Check if the "mon" suffixed interface actually exists
	devs, err := pcap.FindAllDevs()
	if err == nil {
		monName := iface + "mon"
		for _, d := range devs {
			if d.Name == monName {
				return monName
			}
		}
	}

	// If it doesn't exist, iw just changed the mode of the original interface
	return iface
}

// IsAlreadyMonitor returns true if the interface name suggests monitor mode.
func IsAlreadyMonitor(iface string) bool {
	name := strings.ToLower(iface)
	return strings.HasSuffix(name, "mon") || strings.Contains(name, "monitor")
}

// --- Linux implementation ---

func linuxEnableMonitor(iface string) error {
	// 1. Take interface down
	if err := runCmd("ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("ip link down: %w", err)
	}

	// 3. Set monitor mode (try iw first, fallback to iwconfig)
	if err := runCmd("iw", "dev", iface, "set", "type", "monitor"); err != nil {
		if err2 := runCmd("iwconfig", iface, "mode", "monitor"); err2 != nil {
			return fmt.Errorf("iw failed (%v); iwconfig also failed (%v)", err, err2)
		}
	}

	// 4. Bring interface back up
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("ip link up: %w", err)
	}
	return nil
}

func linuxDisableMonitor(iface string) error {
	_ = runCmd("ip", "link", "set", iface, "down")
	_ = runCmd("iw", "dev", iface, "set", "type", "managed")
	_ = runCmd("ip", "link", "set", iface, "up")
	return nil
}

// runCmd executes a system command and returns any error.
func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s", name, args, strings.TrimSpace(string(out)))
	}
	return nil
}
