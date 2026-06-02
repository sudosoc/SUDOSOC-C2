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

	"github.com/sudosoc/SUDOSOC-C2/server/db"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

// BeaconRow is a single row in the beacons table.
type BeaconRow struct {
	ID          string
	Name        string
	Hostname    string
	Username    string
	OS          string
	Transport   string
	Address     string
	LastCheckin string
	NextCheckin string
	Interval    string
}

// BeaconsDataMsg carries a refreshed list of beacons.
type BeaconsDataMsg []BeaconRow

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────

// BeaconsModel holds state for the Beacons panel.
type BeaconsModel struct {
	Data BeaconsDataMsg
}

// NewBeacons creates a zero-value BeaconsModel.
func NewBeacons() BeaconsModel { return BeaconsModel{} }

// Refresh fetches live beacon data from the database.
func (m BeaconsModel) Refresh() tea.Cmd {
	return func() tea.Msg {
		beacons, _ := db.ListBeacons()
		rows := make(BeaconsDataMsg, 0, len(beacons))
		for _, b := range beacons {
			last := time.Unix(b.LastCheckin, 0)
			next := time.Unix(b.NextCheckin, 0)
			rows = append(rows, BeaconRow{
				ID:          b.ID[:8],
				Name:        b.Name,
				Hostname:    b.Hostname,
				Username:    b.Username,
				OS:          b.OS,
				Transport:   b.Transport,
				Address:     b.RemoteAddress,
				LastCheckin: time.Since(last).Round(time.Second).String() + " ago",
				NextCheckin: time.Until(next).Round(time.Second).String(),
				Interval:    (time.Duration(b.Interval) * time.Millisecond).String(),
			})
		}
		return rows
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// View
// ─────────────────────────────────────────────────────────────────────────────

var beaconCols = []struct {
	header string
	width  int
}{
	{"ID",        10},
	{"NAME",      20},
	{"HOSTNAME",  18},
	{"USER",      14},
	{"OS",        10},
	{"TRANSPORT", 10},
	{"LAST",      14},
	{"NEXT",      14},
	{"INTERVAL",  10},
}

func (m BeaconsModel) View(w, h int) string {
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff"))
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaacc")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#555577"))
	text := lipgloss.NewStyle().Foreground(lipgloss.Color("#e0e0e0"))

	var b strings.Builder

	count := fmt.Sprintf("%d beacon(s)", len(m.Data))
	b.WriteString(cyan.Bold(true).Render("Beacons") + "  " + muted.Render(count) + "\n\n")

	if len(m.Data) == 0 {
		b.WriteString(muted.Render("  No beacons registered.\n"))
		return b.String()
	}

	// Header
	row := ""
	for _, col := range beaconCols {
		row += header.Width(col.width).Render(col.header) + " "
	}
	b.WriteString(row + "\n")
	b.WriteString(muted.Render(strings.Repeat("─", w)) + "\n")

	// Rows
	maxRows := h - 5
	for i, brow := range m.Data {
		if i >= maxRows {
			b.WriteString(muted.Render(fmt.Sprintf("  … %d more", len(m.Data)-i)) + "\n")
			break
		}
		line := cyan.Render("◆") + " " +
			text.Width(beaconCols[0].width-2).Render(brow.ID) + " " +
			text.Width(beaconCols[1].width).Render(brow.Name) + " " +
			text.Width(beaconCols[2].width).Render(brow.Hostname) + " " +
			text.Width(beaconCols[3].width).Render(brow.Username) + " " +
			text.Width(beaconCols[4].width).Render(brow.OS) + " " +
			text.Width(beaconCols[5].width).Render(brow.Transport) + " " +
			text.Width(beaconCols[6].width).Render(brow.LastCheckin) + " " +
			text.Width(beaconCols[7].width).Render(brow.NextCheckin) + " " +
			text.Width(beaconCols[8].width).Render(brow.Interval)
		b.WriteString(line + "\n")
	}

	return b.String()
}
