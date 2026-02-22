package iface

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ConnectedBSSID attempts to find the BSSID of the currently connected Wi-Fi network.
func ConnectedBSSID() (net.HardwareAddr, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("ConnectedBSSID only supported on linux")
	}

	// iwconfig output looks like:
	// wlp8s0    IEEE 802.11  ESSID:"MyNetwork"
	//           Mode:Managed  Frequency:2.412 GHz  Access Point: AA:BB:CC:DD:EE:FF
	out, err := exec.Command("iwconfig").CombinedOutput()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`Access Point:\s*([a-fA-F0-9:-]{17})`)
	match := re.FindStringSubmatch(string(out))
	if len(match) < 2 {
		return nil, fmt.Errorf("no connected Access Point found via iwconfig")
	}

	macStr := strings.ReplaceAll(match[1], "-", ":")
	return net.ParseMAC(macStr)
}
