<div align="center">

```
   ██████╗ ███████╗ █████╗ ██████╗      █████╗ ██╗██████╗
   ██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔══██╗██║██╔══██╗
   ██║  ██║█████╗  ███████║██║  ██║    ███████║██║██████╔╝
   ██║  ██║██╔══╝  ██╔══██║██║  ██║    ██╔══██║██║██╔══██╗
   ██████╔╝███████╗██║  ██║██████╔╝    ██║  ██║██║██║  ██║
   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

**A feature-rich 802.11 deauth tool written in Go — built for learning.**

Scans nearby networks, discovers APs and clients, and continuously sends 802.11 deauthentication frames. Includes WPA handshake capture, PMKID harvesting, probe request logging, WIDS defense mode, GPS wardriving, and a live HTTP dashboard.

Inspired by [wifijammer](https://github.com/DanMcInerney/wifijammer).

[![CI](https://github.com/meetsoni15/deadair/actions/workflows/ci.yml/badge.svg)](https://github.com/meetsoni15/deadair/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Built with Bubble Tea](https://img.shields.io/badge/built%20with-Bubble%20Tea-ff69b4)](https://github.com/charmbracelet/bubbletea)

> ⚠️ **For educational and authorized use only.** Sending deauth frames to networks you don't own is illegal. Only use on networks you have explicit permission to test.

</div>

---

## Features

| Category | Feature |
|---|---|
| **Core** | Passive 802.11 scan → AP + client discovery |
| **Core** | Continuous deauth burst (3 frame types: AP→Client, Client→AP, AP→Broadcast) |
| **Core** | Channel hopping (1–11 or 1–13) with lock support |
| **Core** | Live Bubble Tea TUI dashboard |
| **Targeting** | RSSI-based smart targeting (`--min-rssi`) |
| **Targeting** | Lock to single AP (`-a`) or single channel (`-c`) |
| **Capture** | Live `.pcap` file writer — open in Wireshark while running |
| **Capture** | WPA 4-way handshake capture → `.hccapx` (hashcat compatible) |
| **Capture** | Passive PMKID extraction → hashcat 22000 format |
| **Capture** | GPS-tagged wardriving → `warmap.geojson` |
| **Intel** | Probe request logger — reveals client network history → JSON |
| **Defense** | WIDS mode: detect deauth attacks instead of sending them |
| **Dashboard** | HTTP REST API + SSE live dashboard at `localhost:8080` |
| **Advanced** | Multi-interface mode (separate sniff + inject adapters) |
| **Advanced** | Evil twin rogue AP via `hostapd` + `dnsmasq` |

---

## Platform Support

| OS | Monitor Mode | Packet Injection | Notes |
|---|---|---|---|
| **Linux** | ✅ Auto (via `iw`) | ✅ Full | Full functionality |
| **macOS** | ⚠️ Limited | ❌ Kernel-blocked | Sniff-only; use Linux VM for injection |
| **Windows** | ❌ | ❌ | Not supported |

**Recommended setup for macOS users:** [UTM](https://mac.getutm.app) + Ubuntu VM + USB WiFi adapter (Alfa AWUS036ACH).

---

## Requirements

- **Linux** with a wireless adapter supporting monitor mode + injection
- `libpcap` (`apt install libpcap-dev`)
- Root / `sudo`
- **For evil twin:** `hostapd` + `dnsmasq` + a second wireless interface
- **For GPS:** `gpsd` running on `localhost:2947`

---

## Installation

### Pre-built binary (Linux amd64)
```bash
# Download latest release
curl -sL https://github.com/meetsoni15/deadair/releases/latest/download/deadair_linux_amd64.tar.gz | tar xz
sudo ./deadair
```

### Build from source
```bash
git clone https://github.com/meetsoni15/deadair
cd deadair
go build -o deadair .
sudo ./deadair
```

### go install
```bash
go install github.com/meetsoni15/deadair@latest
```

---

## Usage

### Basic — jam everything in range
```bash
sudo deadair
```

### Target a single AP locked to its channel
```bash
sudo deadair -a AA:BB:CC:DD:EE:FF -c 6
```

### Only hit strong signals (RSSI ≥ -70 dBm)
```bash
sudo deadair --min-rssi -70
```

### Record everything to a PCAP (open in Wireshark live)
```bash
sudo deadair --pcap capture.pcap
# In another terminal:
wireshark capture.pcap
```

### Capture WPA handshakes + PMKIDs for offline cracking
```bash
sudo deadair --handshakes ./hs --pmkid pmkids.txt
# After capture:
hashcat -m 2500 hs/*.hccapx wordlist.txt
hashcat -m 22000 pmkids.txt wordlist.txt
```

### Log probe requests (discover client network history)
```bash
sudo deadair --probes probes.json
# On exit, probes.json contains every SSID each client has queried for
```

### Defense: WIDS mode (detect attacks, don't send them)
```bash
sudo deadair --wids --wids-threshold 5
```

### HTTP dashboard alongside TUI
```bash
sudo deadair --api --api-port 8080
# Open http://localhost:8080 in browser — live table + event log
```

### Wardriving with GPS
```bash
# Start gpsd first (with your GPS receiver connected)
gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock
# Then run deadair
sudo deadair --gps --warmap warmap.geojson
# On exit, drag warmap.geojson into https://geojson.io to visualize
```

### Evil twin — rogue AP after first scan
```bash
# Requires a second interface (wlan1) for AP mode + hostapd + dnsmasq
sudo deadair --evil-twin --twin-iface wlan1
```

### Multi-interface mode (fastest — separate sniff + inject)
```bash
sudo deadair -i wlan0mon --inject-iface wlan1mon
```

---

## All Flags

### Core

| Flag | Default | Description |
|---|---|---|
| `-a` | (all) | Target AP MAC — only deauth clients on this AP |
| `-c` | 0 (hop) | Lock to a specific channel |
| `-d` | false | Skip AP→broadcast deauth packets |
| `-i` | auto | Wireless interface (sniff + inject) |
| `-m` | 0 | Max target APs before clearing list (0 = unlimited) |
| `-n` | false | Don't clear list when max is hit |
| `-p` | 1 | Deauth packets per burst per target |
| `-s` | (none) | Skip this MAC address |
| `-t` | 0 | Interval between each packet send |
| `--world` | false | Use channels 1–13 (outside N. America) |

### Targeting

| Flag | Default | Description |
|---|---|---|
| `--min-rssi` | 0 | Skip APs weaker than this dBm (e.g. `-70`), 0 = no filter |

### Capture

| Flag | Default | Description |
|---|---|---|
| `--pcap` | (off) | Write live capture to file (e.g. `capture.pcap`) |
| `--handshakes` | `handshakes/` | Directory to save `.hccapx` handshake files |
| `--pmkid` | (off) | File to append PMKID lines (hashcat 22000 format) |
| `--probes` | (off) | File to save probe request JSON on exit |

### Defense

| Flag | Default | Description |
|---|---|---|
| `--wids` | false | WIDS mode: detect deauth attacks, don't send them |
| `--wids-threshold` | 5 | Frames/sec that trigger a WIDS alert |

### Dashboard

| Flag | Default | Description |
|---|---|---|
| `--api` | false | Enable HTTP dashboard |
| `--api-port` | 8080 | HTTP dashboard port |

### GPS / Wardriving

| Flag | Default | Description |
|---|---|---|
| `--gps` | false | Enable GPS tagging via gpsd |
| `--gps-addr` | `localhost:2947` | gpsd address |
| `--warmap` | `warmap.geojson` | Output file for wardriving map |

### Advanced

| Flag | Default | Description |
|---|---|---|
| `--evil-twin` | false | Enable rogue AP mode after first scan |
| `--twin-iface` | (same as `-i`) | Interface for rogue AP |
| `--inject-iface` | (same as `-i`) | Separate interface for packet injection |

---

## How It Works

### Deauth Loop
For each discovered AP + Client pair, 3 deauth packets are sent:
```
Packet 1: AP  → Client     (AP kicks the client)
Packet 2: Client → AP      (client appears to disassociate)  
Packet 3: AP  → Broadcast  (deauth all clients at once)
```

### WPA Handshake Capture
```
deauth sent → client reconnects → 4-way EAPOL exchange captured
→ ANonce + SNonce + MIC extracted → .hccapx written → crack offline
```

### PMKID Capture (passive — no deauth needed)
```
AP sends EAPOL Message 1 → PMKID extracted from RSN IE
→ appended to pmkids.txt → crack with hashcat -m 22000
```

### WIDS Mode
```
Monitor for deauth bursts → sliding window rate counter per BSSID
→ alert fires if ≥ threshold frames/sec → logged to TUI + console
```

### GPS Wardriving
```
gpsd provides lat/lon fixes → each AP discovery tagged with coordinates
→ on exit: warmap.geojson written → drag into geojson.io to visualize
```

---

## Architecture

```
main.go
  ├── internal/iface/
  │   ├── detect.go       — auto-select wireless interface
  │   ├── monitor.go      — enable/disable monitor mode (Linux: iw)
  │   └── multi.go        — dual-interface coordination
  ├── internal/scanner/
  │   ├── hopper.go       — channel hopping (1–11 or 1–13)
  │   └── sniffer.go      — 802.11 frame capture + event dispatch
  ├── internal/deauth/
  │   └── sender.go       — craft + inject deauth frames (gopacket)
  ├── internal/target/
  │   └── table.go        — thread-safe AP+Client+RSSI store
  ├── internal/capture/
  │   ├── writer.go       — live .pcap file writer
  │   ├── handshake.go    — WPA EAPOL state machine + .hccapx writer
  │   ├── pmkid.go        — passive PMKID extractor
  │   └── geojson.go      — GPS-tagged wardriving map exporter
  ├── internal/probe/
  │   └── log.go          — probe request logger
  ├── internal/wids/
  │   └── detector.go     — deauth burst detector
  ├── internal/api/
  │   └── server.go       — HTTP REST API + SSE live dashboard
  ├── internal/gps/
  │   └── client.go       — gpsd TCP client
  ├── internal/eviltwin/
  │   └── twin.go         — hostapd/dnsmasq rogue AP manager
  └── internal/ui/
      ├── model.go        — Bubble Tea state + messages
      ├── view.go         — TUI render
      └── styles.go       — Lipgloss color palette
```

### TUI Keyboard Shortcuts

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit (restores managed mode, saves logs) |
| `p` | Pause / resume deauth loop |
| `j` / `k` | Navigate AP list |

---

## HTTP Dashboard

When `--api` is enabled, a live dashboard is available at `http://localhost:8080`:
- **`GET /api/targets`** — JSON array of all discovered APs with BSSID, SSID, signal, clients, deauths
- **`GET /api/stats`** — JSON with interface, AP count, total deauths, uptime
- **`GET /events`** — Server-Sent Events stream for live updates
- **`GET /`** — Auto-refreshing HTML dashboard

---

## Built With

| Library | Purpose |
|---|---|
| [gopacket](https://github.com/google/gopacket) | 802.11 packet capture + injection |
| [Bubble Tea](https://github.com/charmbracelet/bubbletea) | TUI framework |
| [Lipgloss](https://github.com/charmbracelet/lipgloss) | Styling |

---

## Legal

This tool is for **authorized penetration testing and educational purposes only**.
- Using this tool against networks you don't own is a criminal offence in most jurisdictions
- Always get explicit written permission before testing
- The author is not responsible for any misuse

---

## License

MIT — see [LICENSE](LICENSE) for details.
