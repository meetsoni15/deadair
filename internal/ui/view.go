package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/meetsoni15/deadair/internal/target"
)

const (
	colBSSID   = 18
	colSSID    = 20
	colCh      = 5
	colClients = 9
	colDeauths = 10
)

// View renders the full TUI.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading deadair..."
	}

	sections := []string{
		m.renderHeader(),
		m.renderStatsBar(),
		m.renderTable(),
		m.renderLogPane(),
		m.renderHelp(),
	}
	return strings.Join(sections, "\n")
}

// renderHeader renders the top title bar.
func (m Model) renderHeader() string {
	title := StyleTitle.Render(" ⚡ deadair ")
	sub := StyleSubtitle.Render(" 802.11 deauth tool — educational use only")
	pause := ""
	if m.Paused {
		pause = "  " + StylePaused.Render(" ⏸ PAUSED ")
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, title, sub, pause)
}

// renderStatsBar renders the interface/channel/count stats row.
func (m Model) renderStatsBar() string {
	aps := m.Table.Count()
	totalDeauths := m.Table.TotalDeauths()

	parts := []string{
		StyleStatKey.Render("Interface: ") + StyleStatAccent.Render(m.Iface),
		StyleStatKey.Render("  Channel: ") + StyleChannel.Render(fmt.Sprintf("%2d", m.Channel)),
		StyleStatKey.Render("  APs: ") + StyleStatValue.Render(fmt.Sprintf("%d", aps)),
		StyleStatKey.Render("  Deauths sent: ") + StyleRiskCritical.Render(fmt.Sprintf("%d", totalDeauths)),
		StyleStatKey.Render("  Uptime: ") + StyleStatValue.Render(m.Uptime()),
	}
	return strings.Join(parts, "") + "\n"
}

// renderTable renders the AP target table.
func (m Model) renderTable() string {
	header := fmt.Sprintf(
		"%-*s  %-*s  %-*s  %-*s  %-*s",
		colBSSID, "BSSID",
		colSSID, "SSID",
		colCh, "Ch",
		colClients, "Clients",
		colDeauths, "Deauths",
	)

	var sb strings.Builder
	sb.WriteString(StyleTableHeader.Render(header))
	sb.WriteString("\n")

	aps := m.Table.All()
	if len(aps) == 0 {
		sb.WriteString(StyleLogText.Render("  Scanning... waiting for beacons\n"))
		return sb.String()
	}

	// Determine how many rows we can show
	maxRows := m.height - 14
	if maxRows < 3 {
		maxRows = 3
	}

	for i, ap := range aps {
		if i >= maxRows {
			sb.WriteString(StyleDimGray().Render(fmt.Sprintf("  ... and %d more\n", len(aps)-maxRows)))
			break
		}

		bssid := truncate(ap.BSSID.String(), colBSSID)
		ssid := truncate(ap.SSID, colSSID)
		if ssid == "" {
			ssid = StyleDimGray().Render("<hidden>")
		}
		ch := fmt.Sprintf("%d", ap.Channel)
		clients := fmt.Sprintf("%d", len(ap.Clients))
		deauths := fmt.Sprintf("%d", ap.Deauths)
		emoji := RiskEmoji(len(ap.Clients))

		row := fmt.Sprintf(
			"%s %-*s  %-*s  %-*s  %-*s  %-*s",
			emoji,
			colBSSID-2, bssid,
			colSSID, ssid,
			colCh-1, ch,
			colClients-1, clients,
			colDeauths, deauths,
		)

		if i == m.selected {
			sb.WriteString(StyleRowSelected.Render(row))
		} else {
			sb.WriteString(RiskStyle(len(ap.Clients)).Render(emoji) + "  " + StyleRowNormal.Render(
				fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s",
					colBSSID-2, bssid,
					colSSID, ssid,
					colCh-1, ch,
					colClients-1, clients,
					colDeauths, deauths,
				),
			))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// renderLogPane renders the recent event log.
func (m Model) renderLogPane() string {
	logLines := m.logs
	maxLogLines := 6
	if len(logLines) > maxLogLines {
		logLines = logLines[len(logLines)-maxLogLines:]
	}

	var sb strings.Builder
	for _, l := range logLines {
		sb.WriteString(StyleLogPrefix.Render("[LOG] "))
		sb.WriteString(StyleLogText.Render(l))
		sb.WriteString("\n")
	}

	content := sb.String()
	if content == "" {
		content = StyleLogText.Render("  No events yet...\n")
	}

	return StyleLogPane.Width(m.width-4).Render(content) + "\n"
}

// renderHelp renders the bottom keybinding hint bar.
func (m Model) renderHelp() string {
	keys := []string{
		StyleHelpKey.Render("q") + StyleHelp.Render(" quit"),
		StyleHelpKey.Render("p") + StyleHelp.Render(" pause"),
		StyleHelpKey.Render("j/k") + StyleHelp.Render(" navigate"),
	}
	return strings.Join(keys, StyleHelp.Render("  │  "))
}

// --- helpers ---

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func renderAPRow(ap *target.AP, selected bool, idx int) string {
	_ = ap
	_ = selected
	_ = idx
	return ""
}

// StyleDimGray returns a dim gray style (convenience).
func StyleDimGray() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
}
