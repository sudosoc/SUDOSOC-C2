package views

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
*/

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

// DashboardDataMsg carries refreshed dashboard statistics.
type DashboardDataMsg struct {
	Sessions  int
	Beacons   int
	Listeners int
	Operators int
	Uptime    string
	FetchedAt time.Time
}

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────

// DashboardModel holds the state for the Dashboard panel.
type DashboardModel struct {
	Data DashboardDataMsg
}

// NewDashboard creates a zero-value DashboardModel.
func NewDashboard() DashboardModel {
	return DashboardModel{}
}

// Refresh returns a Cmd that fetches live stats from the server core.
func (m DashboardModel) Refresh() tea.Cmd {
	return func() tea.Msg {
		sessions := core.Sessions.All()
		beacons, _ := db.ListBeacons()
		listeners := core.Jobs.All()
		operators := core.Clients.ActiveOperators()

		return DashboardDataMsg{
			Sessions:  len(sessions),
			Beacons:   len(beacons),
			Listeners: len(listeners),
			Operators: len(operators),
			Uptime:    time.Since(serverStart).Round(time.Second).String(),
			FetchedAt: time.Now(),
		}
	}
}

// serverStart records when the TUI first loaded — used for uptime display.
var serverStart = time.Now()

// ─────────────────────────────────────────────────────────────────────────────
// View
// ─────────────────────────────────────────────────────────────────────────────

func (m DashboardModel) View(w, h int) string {
	d := m.Data

	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff88")).Bold(true)
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff")).Bold(true)
	orange := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffaa00")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#555577"))
	label := lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaacc"))

	// ── Stat cards ────────────────────────────────────────────────────
	card := func(title, value string, style lipgloss.Style) string {
		return lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#222244")).
			Padding(1, 3).
			Width(18).
			Render(label.Render(title) + "\n" + style.Render(value))
	}

	cards := strings.Join([]string{
		card("Sessions",  fmt.Sprintf("%d", d.Sessions),  green),
		card("Beacons",   fmt.Sprintf("%d", d.Beacons),   cyan),
		card("Listeners", fmt.Sprintf("%d", d.Listeners), orange),
		card("Operators", fmt.Sprintf("%d", d.Operators), green),
	}, "  ")

	// ── ASCII logo ────────────────────────────────────────────────────
	logo := green.Render("SUDOSOC-C2") + "  " +
		muted.Render("v2.0.0 | Precision adversary simulation")

	// ── Info section ──────────────────────────────────────────────────
	info := fmt.Sprintf(
		"%s  %s\n%s  %s",
		label.Render("Uptime:"),
		cyan.Render(d.Uptime),
		label.Render("Refreshed:"),
		muted.Render(d.FetchedAt.Format("15:04:05")),
	)

	// ── Activity bar (sessions as blocks) ────────────────────────────
	activity := renderActivityBar(d.Sessions, w-10, green)

	var b strings.Builder
	b.WriteString(logo)
	b.WriteString("\n\n")
	b.WriteString(cards)
	b.WriteString("\n\n")
	b.WriteString(info)
	b.WriteString("\n\n")
	b.WriteString(label.Render("Active Sessions  "))
	b.WriteString(activity)
	b.WriteString("\n")

	return b.String()
}

// renderActivityBar draws a simple block progress bar for session count.
func renderActivityBar(count, width int, style lipgloss.Style) string {
	maxBar := width - 10
	if maxBar < 1 {
		maxBar = 1
	}
	if count > maxBar {
		count = maxBar
	}
	filled := strings.Repeat("█", count)
	empty := strings.Repeat("░", maxBar-count)
	return style.Render(filled) + lipgloss.NewStyle().Foreground(lipgloss.Color("#333355")).Render(empty)
}
