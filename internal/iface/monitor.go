package iface

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

// OS identifier constants used for runtime.GOOS comparisons.
const (
	osLinux   = "linux"
	osDarwin  = "darwin"
	osWindows = "windows"
)

// monSuffix is the suffix appended by airmon-ng when creating a monitor interface.
// monKeyword is the mode string passed to iw/iwconfig and used for broad name detection.
// iwModeManaged is the managed-mode string used when restoring a NIC to normal operation.
const (
	monSuffix     = "mon"
	monKeyword    = "monitor"
	iwModeManaged = "managed"
)

// Sentinel errors returned by EnableMonitor for well-known OS conditions.
// Callers can use errors.Is to distinguish them.
var (
	// ErrMacOSUnsupported is returned on macOS where kernel restrictions block raw packet injection.
	ErrMacOSUnsupported = errors.New("macOS: raw packet injection is blocked by the kernel; " +
		"sniff-only mode. Use a Linux machine or VM for full functionality")

	// ErrUnsupportedOS is returned on operating systems with no monitor-mode support.
	ErrUnsupportedOS = errors.New("unsupported OS: manually put the interface into monitor mode")
)

// EnableMonitor puts the given interface into monitor mode.
// On Linux it uses `iw` (with iwconfig as fallback).
// On macOS, raw packet injection is kernel-blocked; a warning error is returned.
func EnableMonitor(iface string) error {
	switch runtime.GOOS {
	case osLinux:
		return linuxEnableMonitor(iface)
	case osDarwin:
		return ErrMacOSUnsupported
	default:
		return fmt.Errorf("%w (detected: %s, iface: %s)", ErrUnsupportedOS, runtime.GOOS, iface)
	}
}

// DisableMonitor restores the interface to managed mode.
// On unsupported or macOS systems this is a no-op.
func DisableMonitor(iface string) error {
	switch runtime.GOOS {
	case osLinux:
		return linuxDisableMonitor(iface)
	case osDarwin:
		return nil // no-op — nothing was enabled
	default:
		return nil
	}
}

// MonitorName returns the effective monitor-mode interface name.
// If airmon-ng was used it may have created iface+"mon"; if iw was used
// the original interface name is preserved.
func MonitorName(iface string) string {
	if strings.HasSuffix(iface, monSuffix) {
		return iface
	}

	// Check whether airmon-ng created a separate "<iface>mon" device.
	devs, err := pcap.FindAllDevs()
	if err == nil {
		monName := iface + monSuffix
		for _, d := range devs {
			if d.Name == monName {
				return monName
			}
		}
	}

	// iw keeps the original interface name when switching modes.
	return iface
}

// IsAlreadyMonitor reports whether the interface name implies monitor mode
// (e.g. "wlan0mon" or "monitor0").
func IsAlreadyMonitor(iface string) bool {
	name := strings.ToLower(iface)
	return strings.HasSuffix(name, monSuffix) || strings.Contains(name, monKeyword)
}

// --- Linux implementation ---

func linuxEnableMonitor(iface string) error {
	// 1. Take the interface down.
	if err := runCmd("ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("ip link down: %w", err)
	}

	// 2. Set monitor mode — try iw first, fall back to iwconfig.
	if err := runCmd("iw", "dev", iface, "set", "type", monKeyword); err != nil {
		if err2 := runCmd("iwconfig", iface, "mode", monKeyword); err2 != nil {
			return fmt.Errorf("iw failed (%v); iwconfig also failed (%v)", err, err2)
		}
	}

	// 3. Bring the interface back up.
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("ip link up: %w", err)
	}
	return nil
}

func linuxDisableMonitor(iface string) error {
	_ = runCmd("ip", "link", "set", iface, "down")
	_ = runCmd("iw", "dev", iface, "set", "type", iwModeManaged)
	_ = runCmd("ip", "link", "set", iface, "up")
	return nil
}

// runCmd executes name with args, returning a descriptive error on failure.
func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s", name, args, strings.TrimSpace(string(out)))
	}
	return nil
}
