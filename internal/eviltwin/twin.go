// Package eviltwin manages a rogue AP using hostapd and dnsmasq.
// It generates config files and manages the subprocesses.
// Requires hostapd and dnsmasq to be installed on the Linux system.
// Requires a wireless interface capable of AP mode (or a second adapter).
package eviltwin

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Twin represents a running rogue AP.
type Twin struct {
	SSID    string
	Channel int
	Iface   string
	workDir string

	mu      sync.Mutex
	hostapd *exec.Cmd
	dnsmasq *exec.Cmd
}

// Manager spawns and kills evil twin APs.
type Manager struct {
	mu    sync.Mutex
	twins map[string]*Twin // keyed by SSID
}

// NewManager creates a Twin manager.
func NewManager() *Manager {
	return &Manager{twins: make(map[string]*Twin)}
}

// SpawnTwin starts a rogue AP matching the given AP profile.
// iface is the interface to use (should NOT be the monitor interface).
func (m *Manager) SpawnTwin(bssid net.HardwareAddr, ssid string, channel int, iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.twins[ssid]; ok {
		return nil // already running
	}

	// Create temp dir for config files
	dir, err := os.MkdirTemp("", "deadair-eviltwin-")
	if err != nil {
		return err
	}

	t := &Twin{SSID: ssid, Channel: channel, Iface: iface, workDir: dir}

	if err := t.writeHostapdConf(bssid); err != nil {
		return err
	}
	if err := t.writeDnsmasqConf(); err != nil {
		return err
	}
	if err := t.start(); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}

	m.twins[ssid] = t
	return nil
}

// StopAll kills all running rogue APs and cleans up.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.twins {
		t.stop()
		_ = os.RemoveAll(t.workDir)
	}
	m.twins = make(map[string]*Twin)
}

// --- Twin internals ---

func (t *Twin) writeHostapdConf(bssid net.HardwareAddr) error {
	bssidStr := bssid.String()
	config := fmt.Sprintf(`interface=%s
driver=nl80211
ssid=%s
hw_mode=g
channel=%d
bssid=%s
auth_algs=1
wmm_enabled=0
`, t.Iface, t.SSID, t.Channel, bssidStr)
	return os.WriteFile(filepath.Join(t.workDir, "hostapd.conf"), []byte(config), 0644)
}

func (t *Twin) writeDnsmasqConf() error {
	config := fmt.Sprintf(`interface=%s
dhcp-range=192.168.66.10,192.168.66.100,12h
dhcp-option=3,192.168.66.1
dhcp-option=6,192.168.66.1
no-resolv
server=8.8.8.8
`, t.Iface)
	return os.WriteFile(filepath.Join(t.workDir, "dnsmasq.conf"), []byte(config), 0644)
}

func (t *Twin) start() error {
	// Check hostapd is available
	if _, err := exec.LookPath("hostapd"); err != nil {
		return fmt.Errorf("hostapd not found: install with 'apt install hostapd'")
	}

	t.hostapd = exec.Command("hostapd", filepath.Join(t.workDir, "hostapd.conf"))
	if err := t.hostapd.Start(); err != nil {
		return fmt.Errorf("hostapd start: %w", err)
	}

	// dnsmasq is optional
	if path, err := exec.LookPath("dnsmasq"); err == nil {
		t.dnsmasq = exec.Command(path,
			"--conf-file="+filepath.Join(t.workDir, "dnsmasq.conf"),
			"--no-daemon",
			"--log-facility=/dev/null",
		)
		_ = t.dnsmasq.Start()
	}

	return nil
}

func (t *Twin) stop() {
	if t.dnsmasq != nil && t.dnsmasq.Process != nil {
		_ = t.dnsmasq.Process.Kill()
	}
	if t.hostapd != nil && t.hostapd.Process != nil {
		_ = t.hostapd.Process.Kill()
	}
}

// IsAvailable checks if hostapd is installed.
func IsAvailable() bool {
	_, err := exec.LookPath("hostapd")
	return err == nil
}

// sanitize removes characters unsafe for filenames.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

var _ = sanitize // keep export
