package scanner

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/meetsoni15/deadair/internal/capture"
	"github.com/meetsoni15/deadair/internal/probe"
	"github.com/meetsoni15/deadair/internal/target"
	"github.com/meetsoni15/deadair/internal/wids"
)

// Event types emitted by the sniffer to the UI.
type EventKind int

const (
	EventNewAP EventKind = iota
	EventNewClient
	EventProbe
	EventHandshake
	EventPMKID
	EventWIDS
)

// Event represents a discovery event.
type Event struct {
	Kind    EventKind
	BSSID   net.HardwareAddr
	SSID    string
	Client  net.HardwareAddr
	Channel int
	RSSI    int8
	Message string // for probe/handshake/wids text
}

// Sniffer passively captures 802.11 frames and populates the target table.
type Sniffer struct {
	Iface   string
	Table   *target.Table
	Events  chan Event
	MinRSSI int8 // skip APs weaker than this (0 = no filter)

	// Optional integrations (nil = disabled)
	PCAPWriter   *capture.Writer
	ProbeLog     *probe.Log
	HandshakeCap *capture.HandshakeCapture
	PMKIDCap     *capture.PMKIDCapture
	WIDS         *wids.Detector
	WIDSMode     bool // if true, don't populate targets — just watch for attacks

	handle *pcap.Handle
	done   chan struct{}
}

// NewSniffer creates a Sniffer.
func NewSniffer(iface string, tbl *target.Table) *Sniffer {
	return &Sniffer{
		Iface:  iface,
		Table:  tbl,
		Events: make(chan Event, 256),
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
			// Tee to PCAP file if enabled
			if s.PCAPWriter != nil {
				s.PCAPWriter.Write(pkt)
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

	// Extract RSSI and channel from Radiotap
	var rssi int8
	channel := 0
	if rt := pkt.Layer(layers.LayerTypeRadioTap); rt != nil {
		if rtl, ok := rt.(*layers.RadioTap); ok {
			rssi = int8(rtl.DBMAntennaSignal)
			channel = freqToChannel(int(rtl.ChannelFrequency))
		}
	}

	// --- WIDS: watch for deauth attacks on any AP ---
	if s.WIDS != nil && dot11.Type == layers.Dot11TypeMgmtDeauthentication {
		s.WIDS.Observe(dot11.Address1, dot11.Address2)
		return
	}

	// --- Beacon frames → APs ---
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		bssid := dot11.Address3
		ssid := extractSSID(pkt)
		if isValidMAC(bssid) {
			// RSSI filter
			if s.MinRSSI != 0 && rssi != 0 && rssi < s.MinRSSI {
				return
			}
			if !s.WIDSMode {
				before := s.Table.Count()
				s.Table.AddAP(bssid, ssid, channel, rssi)
				if s.Table.Count() > before {
					s.emit(Event{Kind: EventNewAP, BSSID: bssid, SSID: ssid, Channel: channel, RSSI: rssi})
				}
			}
		}
		return
	}

	// --- Probe Requests → reveal client network history ---
	if dot11.Type == layers.Dot11TypeMgmtProbeReq {
		client := dot11.Address2
		ssid := extractSSID(pkt)
		if isValidMAC(client) && ssid != "" && s.ProbeLog != nil {
			s.ProbeLog.Record(client, ssid)
			s.emit(Event{Kind: EventProbe, Client: client, SSID: ssid,
				Message: client.String() + " → " + ssid})
		}
		return
	}

	// --- Data frames → discover clients ---
	if dot11.Type == layers.Dot11TypeData || dot11.Type == layers.Dot11TypeDataQOSData {
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

		// Check for EAPOL inside the data frame (handshake/PMKID capture)
		payload := dot11.Payload
		if len(payload) > 8 && binary.BigEndian.Uint16(payload[6:8]) == 0x888e {
			eapol := payload[8:] // skip LLC header
			s.handleEAPOL(apMAC, clientMAC, eapol)
		}

		if !s.WIDSMode {
			s.Table.AddClient(apMAC, clientMAC)
			s.emit(Event{Kind: EventNewClient, BSSID: apMAC, Client: clientMAC, Channel: channel})
		}
	}
}

func (s *Sniffer) handleEAPOL(bssid, client net.HardwareAddr, payload []byte) {
	// WPA Handshake capture
	if s.HandshakeCap != nil {
		if complete, ssid := s.HandshakeCap.ObserveEAPOL(bssid, client, payload); complete {
			s.emit(Event{Kind: EventHandshake, BSSID: bssid, Client: client, SSID: ssid,
				Message: "🤝 Handshake: " + ssid + " saved to handshakes/"})
		}
	}

	// PMKID capture (passive)
	if s.PMKIDCap != nil {
		if entry := s.PMKIDCap.ObserveEAPOL(bssid, client, payload); entry != nil {
			s.emit(Event{Kind: EventPMKID, BSSID: bssid, Client: client, SSID: entry.SSID,
				Message: "🔑 PMKID: " + entry.SSID + " → pmkids.txt"})
		}
	}
}

func (s *Sniffer) emit(e Event) {
	select {
	case s.Events <- e:
	default:
	}
}

// extractSSID pulls the SSID from a beacon/probe frame's information elements.
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

// freqToChannel converts a Wi-Fi frequency in MHz to a 2.4GHz/5GHz channel number.
func freqToChannel(freq int) int {
	switch {
	case freq == 2484:
		return 14
	case freq >= 2412 && freq <= 2472:
		return (freq-2412)/5 + 1
	case freq >= 5180 && freq <= 5825:
		return (freq - 5000) / 5
	}
	return 0
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
