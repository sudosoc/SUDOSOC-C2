package views

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
*/

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/sudosoc/SUDOSOC-C2/server/core"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

// ListenerRow is a single row in the listeners table.
type ListenerRow struct {
	ID       int
	Name     string
	Protocol string
	Port     uint16
	Domains  string
}

// ListenersDataMsg carries a refreshed list of listeners.
type ListenersDataMsg []ListenerRow

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────

// ListenersModel holds state for the Listeners panel.
type ListenersModel struct {
	Data ListenersDataMsg
}

// NewListeners creates a zero-value ListenersModel.
func NewListeners() ListenersModel { return ListenersModel{} }

// Refresh fetches live listener (job) data from core.
func (m ListenersModel) Refresh() tea.Cmd {
	return func() tea.Msg {
		jobs := core.Jobs.All()
		rows := make(ListenersDataMsg, 0, len(jobs))
		for _, j := range jobs {
			domains := strings.Join(j.Domains, ", ")
			if domains == "" {
				domains = "-"
			}
			rows = append(rows, ListenerRow{
				ID:       j.ID,
				Name:     j.Name,
				Protocol: j.Protocol,
				Port:     j.Port,
				Domains:  domains,
			})
		}
		return rows
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// View
// ─────────────────────────────────────────────────────────────────────────────

func (m ListenersModel) View(w, h int) string {
	orange := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffaa00"))
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaacc")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#555577"))
	text := lipgloss.NewStyle().Foreground(lipgloss.Color("#e0e0e0"))

	cols := []struct {
		h string
		w int
	}{
		{"ID", 6}, {"NAME", 22}, {"PROTOCOL", 12}, {"PORT", 8}, {"DOMAINS", 30},
	}

	var b strings.Builder

	count := fmt.Sprintf("%d listener(s)", len(m.Data))
	b.WriteString(orange.Bold(true).Render("Listeners") + "  " + muted.Render(count) + "\n\n")

	if len(m.Data) == 0 {
		b.WriteString(muted.Render("  No active listeners.\n"))
		return b.String()
	}

	// Header row
	row := ""
	for _, col := range cols {
		row += header.Width(col.w).Render(col.h) + " "
	}
	b.WriteString(row + "\n")
	b.WriteString(muted.Render(strings.Repeat("─", w)) + "\n")

	maxRows := h - 5
	for i, l := range m.Data {
		if i >= maxRows {
			b.WriteString(muted.Render(fmt.Sprintf("  … %d more", len(m.Data)-i)) + "\n")
			break
		}
		line := orange.Render("▶") + " " +
			text.Width(cols[0].w-2).Render(fmt.Sprintf("%d", l.ID)) + " " +
			text.Width(cols[1].w).Render(l.Name) + " " +
			text.Width(cols[2].w).Render(l.Protocol) + " " +
			text.Width(cols[3].w).Render(fmt.Sprintf("%d", l.Port)) + " " +
			text.Width(cols[4].w).Render(l.Domains)
		b.WriteString(line + "\n")
	}

	return b.String()
}
