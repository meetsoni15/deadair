package scanner

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/meetsoni15/deadair/internal/target"
)

// Event types emitted by the sniffer to the UI.
type EventKind int

const (
	EventNewAP EventKind = iota
	EventNewClient
)

// Event represents a discovery event.
type Event struct {
	Kind    EventKind
	BSSID   net.HardwareAddr
	SSID    string
	Client  net.HardwareAddr
	Channel int
}

// Sniffer passively captures 802.11 frames and populates the target table.
type Sniffer struct {
	Iface  string
	Table  *target.Table
	Events chan Event

	handle *pcap.Handle
	done   chan struct{}
}

// NewSniffer creates a Sniffer.
func NewSniffer(iface string, tbl *target.Table) *Sniffer {
	return &Sniffer{
		Iface:  iface,
		Table:  tbl,
		Events: make(chan Event, 128),
		done:   make(chan struct{}),
	}
}

// Run opens the pcap handle and starts sniffing. Call in a goroutine.
func (s *Sniffer) Run() error {
	handle, err := pcap.OpenLive(s.Iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	s.handle = handle
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, layers.LayerTypeRadioTap)
	src.DecodeOptions.Lazy = true
	src.DecodeOptions.NoCopy = true

	for {
		select {
		case <-s.done:
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil
			}
			s.processPacket(pkt)
		}
	}
}

// Stop signals the sniffer to stop.
func (s *Sniffer) Stop() {
	close(s.done)
	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *Sniffer) processPacket(pkt gopacket.Packet) {
	dot11Layer := pkt.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11, _ := dot11Layer.(*layers.Dot11)

	// Extract channel from Radiotap if available
	channel := 0
	if rt := pkt.Layer(layers.LayerTypeRadioTap); rt != nil {
		if rtl, ok := rt.(*layers.RadioTap); ok {
			channel = int(rtl.ChannelFrequency)
		}
	}

	// --- Beacon frames reveal APs ---
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		bssid := dot11.Address3
		ssid := extractSSID(pkt)
		if isValidMAC(bssid) {
			before := s.Table.Count()
			s.Table.AddAP(bssid, ssid, channel)
			if s.Table.Count() > before {
				s.emit(Event{Kind: EventNewAP, BSSID: bssid, SSID: ssid, Channel: channel})
			}
		}
		return
	}

	// --- Data / QoS Data frames reveal clients ---
	if dot11.Type == layers.Dot11TypeData || dot11.Type == layers.Dot11TypeDataQOSData {
		// ToDS=0, FromDS=1 → Address1=dest, Address2=AP, Address3=src(client)
		// ToDS=1, FromDS=0 → Address1=AP, Address2=src(client), Address3=dest
		var apMAC, clientMAC net.HardwareAddr
		switch {
		case dot11.Flags.FromDS() && !dot11.Flags.ToDS():
			apMAC = dot11.Address2
			clientMAC = dot11.Address3
		case !dot11.Flags.FromDS() && dot11.Flags.ToDS():
			apMAC = dot11.Address1
			clientMAC = dot11.Address2
		default:
			return
		}
		if !isValidMAC(apMAC) || !isValidMAC(clientMAC) || isBroadcast(clientMAC) {
			return
		}
		s.Table.AddClient(apMAC, clientMAC)
		s.emit(Event{Kind: EventNewClient, BSSID: apMAC, Client: clientMAC, Channel: channel})
	}
}

func (s *Sniffer) emit(e Event) {
	select {
	case s.Events <- e:
	default: // drop if channel is full; non-blocking
	}
}

// extractSSID pulls the SSID from a beacon frame's information elements.
// gopacket v1.1.19 exposes IEs as separate layers — we scan all layers.
func extractSSID(pkt gopacket.Packet) string {
	for _, layer := range pkt.Layers() {
		if ie, ok := layer.(*layers.Dot11InformationElement); ok {
			if ie.ID == layers.Dot11InformationElementIDSSID {
				return string(ie.Info)
			}
		}
	}
	return ""
}

func isValidMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 &&
		!(mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
			mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
}

func isBroadcast(mac net.HardwareAddr) bool {
	return len(mac) == 6 &&
		mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
		mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff
}
