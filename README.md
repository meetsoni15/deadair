<div align="center">

```
   ██████╗ ███████╗ █████╗ ██████╗      █████╗ ██╗██████╗
   ██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔══██╗██║██╔══██╗
   ██║  ██║█████╗  ███████║██║  ██║    ███████║██║██████╔╝
   ██║  ██║██╔══╝  ██╔══██║██║  ██║    ██╔══██║██║██╔══██╗
   ██████╔╝███████╗██║  ██║██████╔╝    ██║  ██║██║██║  ██║
   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

**Continuously jam all WiFi clients/APs — built in Go for learning.**

Sends 802.11 deauthentication frames to disconnect devices from their access points.
Inspired by [wifijammer](https://github.com/DanMcInerney/wifijammer).

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Built with Bubble Tea](https://img.shields.io/badge/built%20with-Bubble%20Tea-ff69b4)](https://github.com/charmbracelet/bubbletea)

> ⚠️ **For educational and authorized use only.** Sending deauth frames to networks you don't own is illegal. Only use on networks you control.

</div>

---

## What is deadair?

`deadair` scans nearby 802.11 networks, discovers access points and their connected clients, and continuously sends deauthentication frames to disconnect them. It has a live TUI dashboard showing discovered targets and deauth counts in real time.

It's a Go reimplementation of the Python tool [wifijammer](https://github.com/DanMcInerney/wifijammer), built as a learning project to explore:
- Raw packet crafting with `gopacket`
- 802.11 management frame injection
- Concurrent goroutine architecture
- Terminal UI with Bubble Tea

---

## Requirements

- **Linux** (full support — injection + monitor mode)
- **macOS** (build compiles; raw injection is kernel-blocked — sniff-only)
- A wireless card that supports **monitor mode** and **packet injection**
- `libpcap` installed (`apt install libpcap-dev` / `brew install libpcap`)
- Root / `sudo` to open raw sockets

---

## Installation

### Using `go install`
```bash
go install github.com/meetsoni15/deadair@latest
```

### Build from Source
```bash
git clone https://github.com/meetsoni15/deadair
cd deadair
go build -o deadair .
```

---

## Usage

```bash
# Scan everything on current channel set (auto-detect interface)
sudo deadair

# Target only one AP, locked to its channel
sudo deadair -a AA:BB:CC:DD:EE:FF -c 6

# Use 5 packets per burst, no broadcast deauth
sudo deadair -p 5 -d

# Use outside North America (channels 1–13)
sudo deadair --world

# Specify interface manually
sudo deadair -i wlan0
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-a` | (all) | Target AP MAC — only deauth clients on this AP |
| `-c` | 0 (hop) | Lock to a specific channel |
| `-d` | false | Skip AP→broadcast deauth packets |
| `-i` | auto | Wireless interface name |
| `-m` | 0 | Max target APs before clearing list (0 = unlimited) |
| `-n` | false | Don't clear list when max is hit |
| `-p` | 1 | Deauth packets per burst per target |
| `-s` | (none) | Skip this MAC address |
| `-t` | 0 | Interval between each packet send |
| `--world` | false | Use channels 1–13 (outside N. America) |

---

## How It Works

For each discovered AP + Client pair, deadair sends **3 deauth packets**:

```
Packet 1: AP  → Client     (AP kicks the client)
Packet 2: Client → AP      (client appears to disassociate)
Packet 3: AP  → Broadcast  (deauth all clients at once)
```

Each packet is a raw `Radiotap / 802.11 Deauth` frame injected via `libpcap`.

### Architecture

```
main.go
  ├── iface/detect.go    — auto-select wireless interface
  ├── iface/monitor.go   — enable/disable monitor mode (Linux: iw)
  ├── scanner/hopper.go  — channel hopping goroutine (1–11 or 1–13)
  ├── scanner/sniffer.go — passive 802.11 sniff → target table
  ├── deauth/sender.go   — craft + inject deauth frames via gopacket
  ├── target/table.go    — thread-safe AP+Client store
  └── ui/               — Bubble Tea TUI dashboard
```

### Keyboard Shortcuts (TUI)

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit (restores managed mode) |
| `p` | Pause / resume deauth loop |
| `j` / `k` | Navigate AP list |

---

## Terminal Compatibility

Any modern terminal with true color support:
- [Ghostty](https://ghostty.org) — Excellent
- [Kitty](https://sw.kovidgoyal.net/kitty/) — Excellent
- [WezTerm](https://wezfurlong.org/wezterm/) — Excellent
- [iTerm2](https://iterm2.com) — Great

---

## Built With

| Library | Purpose |
|---|---|
| [gopacket](https://github.com/google/gopacket) | 802.11 packet capture + injection |
| [Bubble Tea](https://github.com/charmbracelet/bubbletea) | TUI framework |
| [Lipgloss](https://github.com/charmbracelet/lipgloss) | Styling |

---

## License

MIT — see [LICENSE](LICENSE) for details.
