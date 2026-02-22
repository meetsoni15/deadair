// Package capture provides live PCAP file writing.
// Frames tee'd from the sniffer are written to a .pcap file that can
// be opened in Wireshark — even while deadair is still running.
package capture

import (
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Writer writes raw 802.11+Radiotap frames to a .pcap file.
type Writer struct {
	mu     sync.Mutex
	file   *os.File
	writer *pcapgo.Writer
}

// NewWriter opens path for writing and writes the pcap global header.
// Call Close() when done. Returns nil, nil if path is empty (disabled).
func NewWriter(path string) (*Writer, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Writer{file: f, writer: w}, nil
}

// Write saves a captured packet to the pcap file.
// Safe to call from multiple goroutines.
func (w *Writer) Write(pkt gopacket.Packet) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.writer.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
}

// Close flushes and closes the pcap file.
func (w *Writer) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.file.Close()
}
