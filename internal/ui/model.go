package ui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/meetsoni15/deadair/internal/target"
)

// --- Messages ---

// TickMsg fires every second to refresh the display.
type TickMsg time.Time

// APDiscoveredMsg signals a new AP was found.
type APDiscoveredMsg struct {
	BSSID   string
	SSID    string
	Channel int
}

// ClientDiscoveredMsg signals a new client was found.
type ClientDiscoveredMsg struct {
	BSSID  string
	Client string
}

// DeauthSentMsg signals a deauth burst was completed.
type DeauthSentMsg struct {
	BSSID string
	Count int
}

// ChannelHopMsg signals the channel changed.
type ChannelHopMsg struct {
	Channel int
}

// LogMsg is a generic log line.
type LogMsg struct {
	Text string
}

// ErrorMsg carries a fatal error to the TUI.
type ErrorMsg struct {
	Err error
}

// --- Model ---

const maxLogs = 50

// Model is the Bubble Tea application model.
type Model struct {
	Table     *target.Table
	Iface     string
	Channel   int
	Paused    bool
	width     int
	height    int
	logs      []string
	startTime time.Time
	selected  int
}

// New creates the initial TUI model.
func New(tbl *target.Table, iface string) Model {
	return Model{
		Table:     tbl,
		Iface:     iface,
		startTime: time.Now(),
		logs:      make([]string, 0, maxLogs),
	}
}

// Init starts the periodic tick.
func (m Model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles all incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case TickMsg:
		return m, tick()

	case ChannelHopMsg:
		m.Channel = msg.Channel
		m.addLog(fmt.Sprintf("↔ Channel → %d", msg.Channel))

	case APDiscoveredMsg:
		m.addLog(fmt.Sprintf("📡 New AP: %s (%q) ch%d", msg.BSSID, msg.SSID, msg.Channel))

	case ClientDiscoveredMsg:
		m.addLog(fmt.Sprintf("💻 New client %s on %s", msg.Client, msg.BSSID))

	case DeauthSentMsg:
		m.addLog(fmt.Sprintf("💥 Deauth ×%d → %s", msg.Count, msg.BSSID))

	case LogMsg:
		m.addLog(msg.Text)

	case ErrorMsg:
		m.addLog(fmt.Sprintf("❌ Error: %v", msg.Err))

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.Paused = !m.Paused
		case "j", "down":
			aps := m.Table.All()
			if m.selected < len(aps)-1 {
				m.selected++
			}
		case "k", "up":
			if m.selected > 0 {
				m.selected--
			}
		}
	}

	return m, nil
}

func (m *Model) addLog(line string) {
	m.logs = append(m.logs, line)
	if len(m.logs) > maxLogs {
		m.logs = m.logs[len(m.logs)-maxLogs:]
	}
}

// IsPaused is safe to read from outside goroutines.
func (m *Model) IsPaused() bool {
	return m.Paused
}

// Uptime returns a formatted elapsed time string.
func (m Model) Uptime() string {
	d := time.Since(m.startTime).Round(time.Second)
	h := int(d.Hours())
	min := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, min, sec)
}
