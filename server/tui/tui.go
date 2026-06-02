// Package tui implements the SUDOSOC-C2 bubbletea-based terminal dashboard.
//
// Launch with:  sudosoc-server --tui
//
// Navigation:
//
//	Tab / Shift+Tab   cycle panels
//	1-5               jump to panel by number
//	r                 refresh current panel
//	?                 toggle help
//	q / Ctrl+C        quit
package tui

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/sudosoc/SUDOSOC-C2/server/tui/views"
)

// ─────────────────────────────────────────────────────────────────────────────
// Colour palette
// ─────────────────────────────────────────────────────────────────────────────

var (
	colorBg      = lipgloss.Color("#0a0a0f")
	colorPrimary = lipgloss.Color("#00ff88")
	colorAccent  = lipgloss.Color("#00d4ff")
	colorMuted   = lipgloss.Color("#555577")
	colorText    = lipgloss.Color("#e0e0e0")
	colorBorder  = lipgloss.Color("#222244")
)

// ─────────────────────────────────────────────────────────────────────────────
// Styles
// ─────────────────────────────────────────────────────────────────────────────

var (
	styleTitle = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Bold(true).
			Padding(0, 1)

	styleTabActive = lipgloss.NewStyle().
			Foreground(colorBg).
			Background(colorPrimary).
			Bold(true).
			Padding(0, 2)

	styleTabInactive = lipgloss.NewStyle().
				Foreground(colorMuted).
				Padding(0, 2)

	styleStatusBar = lipgloss.NewStyle().
			Foreground(colorMuted).
			Background(lipgloss.Color("#111122")).
			Padding(0, 1)

	styleBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(1, 2)
)

// Suppress "declared and not used" for colour vars referenced only in styles.
var _ = colorText
var _ = colorAccent

// ─────────────────────────────────────────────────────────────────────────────
// Panel definitions
// ─────────────────────────────────────────────────────────────────────────────

type panel int

const (
	panelDashboard panel = iota
	panelSessions
	panelBeacons
	panelListeners
	panelLoot
	panelCount
)

var panelNames = [panelCount]string{
	"[1] Dashboard",
	"[2] Sessions",
	"[3] Beacons",
	"[4] Listeners",
	"[5] Loot",
}

// ─────────────────────────────────────────────────────────────────────────────
// Tick message for periodic refresh
// ─────────────────────────────────────────────────────────────────────────────

type tickMsg time.Time

func doTick() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Root model
// ─────────────────────────────────────────────────────────────────────────────

// model is the root bubbletea model for the SUDOSOC TUI.
type model struct {
	active   panel
	width    int
	height   int
	showHelp bool

	dashboard views.DashboardModel
	sessions  views.SessionsModel
	beacons   views.BeaconsModel
	listeners views.ListenersModel
	loot      views.LootModel
}

// initialModel returns a model with all panels initialised.
func initialModel() model {
	return model{
		active:    panelDashboard,
		dashboard: views.NewDashboard(),
		sessions:  views.NewSessions(),
		beacons:   views.NewBeacons(),
		listeners: views.NewListeners(),
		loot:      views.NewLoot(),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Init — bubbletea v2 signature: Init() tea.Cmd
// ─────────────────────────────────────────────────────────────────────────────

func (m model) Init() tea.Cmd {
	return tea.Batch(
		doTick(),
		m.dashboard.Refresh(),
		m.sessions.Refresh(),
		m.beacons.Refresh(),
		m.listeners.Refresh(),
		m.loot.Refresh(),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Update
// ─────────────────────────────────────────────────────────────────────────────

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(doTick(), m.refreshActive())

	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
		case "r":
			return m, m.refreshActive()
		case "tab":
			m.active = (m.active + 1) % panelCount
			return m, m.refreshActive()
		case "shift+tab":
			m.active = (m.active - 1 + panelCount) % panelCount
			return m, m.refreshActive()
		case "1":
			m.active = panelDashboard
			return m, m.refreshActive()
		case "2":
			m.active = panelSessions
			return m, m.refreshActive()
		case "3":
			m.active = panelBeacons
			return m, m.refreshActive()
		case "4":
			m.active = panelListeners
			return m, m.refreshActive()
		case "5":
			m.active = panelLoot
			return m, m.refreshActive()
		}

	// ── Panel data updates ─────────────────────────────────────────────
	case views.DashboardDataMsg:
		m.dashboard.Data = msg
	case views.SessionsDataMsg:
		m.sessions.Data = msg
	case views.BeaconsDataMsg:
		m.beacons.Data = msg
	case views.ListenersDataMsg:
		m.listeners.Data = msg
	case views.LootDataMsg:
		m.loot.Data = msg
	}

	return m, nil
}

// refreshActive returns the Cmd that fetches fresh data for the active panel.
func (m model) refreshActive() tea.Cmd {
	switch m.active {
	case panelDashboard:
		return m.dashboard.Refresh()
	case panelSessions:
		return m.sessions.Refresh()
	case panelBeacons:
		return m.beacons.Refresh()
	case panelListeners:
		return m.listeners.Refresh()
	case panelLoot:
		return m.loot.Refresh()
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// View — bubbletea v2 signature: View() tea.View
// ─────────────────────────────────────────────────────────────────────────────

func (m model) View() tea.View {
	v := tea.NewView(m.renderAll())
	v.AltScreen = true // use the alternate screen buffer (declarative in v2)
	return v
}

func (m model) renderAll() string {
	if m.width == 0 {
		return "Loading SUDOSOC-C2 TUI…"
	}

	var b strings.Builder

	b.WriteString(m.renderHeader())
	b.WriteString("\n")
	b.WriteString(m.renderTabs())
	b.WriteString("\n\n")

	contentH := m.height - 7
	if contentH < 5 {
		contentH = 5
	}
	b.WriteString(m.renderPanel(contentH))
	b.WriteString("\n")
	b.WriteString(m.renderStatusBar())

	if m.showHelp {
		b.WriteString("\n\n")
		b.WriteString(m.renderHelp())
	}

	return b.String()
}

func (m model) renderHeader() string {
	logo    := styleTitle.Render("SUDOSOC-C2")
	version := lipgloss.NewStyle().Foreground(colorMuted).Render("v2.0.0")
	tagline := lipgloss.NewStyle().Foreground(colorAccent).Italic(true).Render(
		"Precision adversary simulation. Zero compromise.",
	)
	pad := strings.Repeat(" ", tuiMax(0, m.width-
		lipgloss.Width(logo)-lipgloss.Width(version)-lipgloss.Width(tagline)-4))
	return logo + "  " + tagline + pad + version
}

func (m model) renderTabs() string {
	tabs := make([]string, panelCount)
	for i, name := range panelNames {
		if panel(i) == m.active {
			tabs[i] = styleTabActive.Render(name)
		} else {
			tabs[i] = styleTabInactive.Render(name)
		}
	}
	return strings.Join(tabs, " ")
}

func (m model) renderPanel(h int) string {
	w := m.width - 4
	if w < 20 {
		w = 20
	}
	var content string
	switch m.active {
	case panelDashboard:
		content = m.dashboard.View(w, h)
	case panelSessions:
		content = m.sessions.View(w, h)
	case panelBeacons:
		content = m.beacons.View(w, h)
	case panelListeners:
		content = m.listeners.View(w, h)
	case panelLoot:
		content = m.loot.View(w, h)
	}
	return styleBorder.Width(m.width - 2).Render(content)
}

func (m model) renderStatusBar() string {
	left  := "  Tab/1-5: panel  r: refresh  ?: help  q: quit"
	right := fmt.Sprintf("  %s  ", time.Now().Format("15:04:05"))
	pad   := strings.Repeat(" ", tuiMax(0, m.width-len(left)-len(right)))
	return styleStatusBar.Width(m.width).Render(left + pad + right)
}

func (m model) renderHelp() string {
	help := "\n  Keyboard shortcuts\n" +
		"  ──────────────────\n" +
		"  Tab / Shift+Tab   Next / previous panel\n" +
		"  1-5               Jump to panel directly\n" +
		"  r                 Refresh current panel\n" +
		"  ?                 Toggle this help\n" +
		"  q / Ctrl+C        Quit TUI\n"
	return lipgloss.NewStyle().
		Foreground(colorText).
		Background(lipgloss.Color("#111133")).
		Padding(1, 3).
		Render(help)
}

func tuiMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Start — entry point called from server/cli/cli.go
// ─────────────────────────────────────────────────────────────────────────────

// Start launches the bubbletea TUI and blocks until the user quits.
func Start() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("[!] TUI error: %v\n", err)
	}
}
