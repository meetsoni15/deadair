package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Base colors
	colorRed     = lipgloss.Color("#FF4D4D")
	colorOrange  = lipgloss.Color("#FF944D")
	colorYellow  = lipgloss.Color("#FFD700")
	colorGreen   = lipgloss.Color("#4DFF91")
	colorCyan    = lipgloss.Color("#4DD9FF")
	colorPurple  = lipgloss.Color("#B04DFF")
	colorWhite   = lipgloss.Color("#FAFAFA")
	colorDimGray = lipgloss.Color("#555555")
	colorDark    = lipgloss.Color("#111111")
	colorBorder  = lipgloss.Color("#333333")

	// Title bar
	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan).
			Background(colorDark).
			Padding(0, 1)

	StyleSubtitle = lipgloss.NewStyle().
			Foreground(colorDimGray).
			Italic(true)

	// Stats bar
	StyleStatKey = lipgloss.NewStyle().
			Foreground(colorDimGray)

	StyleStatValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite)

	StyleStatAccent = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan)

	// Table header
	StyleTableHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorDimGray).
				BorderStyle(lipgloss.NormalBorder()).
				BorderBottom(true).
				BorderForeground(colorBorder)

	// Table rows
	StyleRowSelected = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorCyan).
				Background(lipgloss.Color("#1A1A2E"))

	StyleRowNormal = lipgloss.NewStyle().
			Foreground(colorWhite)

	// Risk colors
	StyleRiskCritical = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
	StyleRiskHigh     = lipgloss.NewStyle().Bold(true).Foreground(colorOrange)
	StyleRiskMedium   = lipgloss.NewStyle().Foreground(colorYellow)
	StyleRiskLow      = lipgloss.NewStyle().Foreground(colorGreen)

	// Log pane
	StyleLogPane = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	StyleLogPrefix = lipgloss.NewStyle().
			Foreground(colorPurple).
			Bold(true)

	StyleLogText = lipgloss.NewStyle().
			Foreground(colorDimGray)

	StyleLogHighlight = lipgloss.NewStyle().
				Foreground(colorCyan)

	// Help bar
	StyleHelp = lipgloss.NewStyle().
			Foreground(colorDimGray).
			Margin(0, 1)

	StyleHelpKey = lipgloss.NewStyle().
			Foreground(colorYellow).
			Bold(true)

	// Outer box
	StyleOuter = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	// Channel bubble
	StyleChannel = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPurple)

	// Paused badge
	StylePaused = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorOrange).
			Background(lipgloss.Color("#2A1A00")).
			Padding(0, 1)
)

// RiskStyle returns the appropriate lipgloss style for a client count.
func RiskStyle(clients int) lipgloss.Style {
	switch {
	case clients >= 5:
		return StyleRiskCritical
	case clients >= 3:
		return StyleRiskHigh
	case clients >= 1:
		return StyleRiskMedium
	default:
		return StyleRiskLow
	}
}

// RiskEmoji returns an emoji for a client count.
func RiskEmoji(clients int) string {
	switch {
	case clients >= 5:
		return "🔴"
	case clients >= 3:
		return "🟠"
	case clients >= 1:
		return "🟡"
	default:
		return "🟢"
	}
}
