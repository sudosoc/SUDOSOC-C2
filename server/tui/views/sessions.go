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
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

// SessionRow is a single row in the sessions table.
type SessionRow struct {
	ID        string
	Name      string
	Hostname  string
	Username  string
	OS        string
	Arch      string
	Transport string
	Address   string
	LastSeen  string
	Dead      bool
}

// SessionsDataMsg carries a refreshed list of sessions.
type SessionsDataMsg []SessionRow

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────

// SessionsModel holds the state for the Sessions panel.
type SessionsModel struct {
	Data   SessionsDataMsg
	cursor int
}

// NewSessions creates a zero-value SessionsModel.
func NewSessions() SessionsModel {
	return SessionsModel{}
}

// Refresh returns a Cmd that loads live sessions from core.
func (m SessionsModel) Refresh() tea.Cmd {
	return func() tea.Msg {
		all := core.Sessions.All()
		rows := make(SessionsDataMsg, 0, len(all))
		for _, s := range all {
			lastSeen := time.Since(s.LastCheckin()).Round(time.Second).String() + " ago"
			rows = append(rows, SessionRow{
				ID:        s.ID[:8],
				Name:      s.Name,
				Hostname:  s.Hostname,
				Username:  s.Username,
				OS:        s.OS,
				Arch:      s.Arch,
				Transport: s.Connection.Transport,
				Address:   s.Connection.RemoteAddress,
				LastSeen:  lastSeen,
				Dead:      s.IsDead(),
			})
		}
		return rows
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// View
// ─────────────────────────────────────────────────────────────────────────────

var sessionCols = []struct {
	header string
	width  int
}{
	{"ID",        10},
	{"NAME",      20},
	{"HOSTNAME",  18},
	{"USER",      14},
	{"OS/ARCH",   12},
	{"TRANSPORT", 10},
	{"ADDRESS",   20},
	{"LAST SEEN", 16},
}

func (m SessionsModel) View(w, h int) string {
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff88"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4444"))
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaacc")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#555577"))

	var b strings.Builder

	// Panel title
	count := fmt.Sprintf("%d session(s)", len(m.Data))
	b.WriteString(green.Bold(true).Render("Sessions") + "  " + muted.Render(count) + "\n\n")

	if len(m.Data) == 0 {
		b.WriteString(muted.Render("  No active sessions.\n"))
		return b.String()
	}

	// Header row
	row := ""
	for _, col := range sessionCols {
		row += header.Width(col.width).Render(col.header) + " "
	}
	b.WriteString(row + "\n")
	b.WriteString(muted.Render(strings.Repeat("─", w)) + "\n")

	// Data rows
	maxRows := h - 5
	for i, s := range m.Data {
		if i >= maxRows {
			b.WriteString(muted.Render(fmt.Sprintf("  … %d more", len(m.Data)-i)) + "\n")
			break
		}

		statusIcon := green.Render("●")
		rowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#e0e0e0"))
		if s.Dead {
			statusIcon = red.Render("●")
			rowStyle = muted
		}

		osArch := s.OS + "/" + s.Arch
		line := statusIcon + " " +
			rowStyle.Width(sessionCols[0].width-2).Render(s.ID) + " " +
			rowStyle.Width(sessionCols[1].width).Render(s.Name) + " " +
			rowStyle.Width(sessionCols[2].width).Render(s.Hostname) + " " +
			rowStyle.Width(sessionCols[3].width).Render(s.Username) + " " +
			rowStyle.Width(sessionCols[4].width).Render(osArch) + " " +
			rowStyle.Width(sessionCols[5].width).Render(s.Transport) + " " +
			rowStyle.Width(sessionCols[6].width).Render(s.Address) + " " +
			rowStyle.Width(sessionCols[7].width).Render(s.LastSeen)

		b.WriteString(line + "\n")
	}

	return b.String()
}
