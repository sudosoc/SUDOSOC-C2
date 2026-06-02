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

	"github.com/sudosoc/SUDOSOC-C2/server/loot"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

// LootRow is a single row in the loot table.
type LootRow struct {
	ID       string
	Name     string
	Type     string
	Size     string
}

// LootDataMsg carries a refreshed loot list.
type LootDataMsg []LootRow

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────

// LootModel holds state for the Loot panel.
type LootModel struct {
	Data LootDataMsg
}

// NewLoot creates a zero-value LootModel.
func NewLoot() LootModel { return LootModel{} }

// Refresh fetches the current loot list from the loot store.
func (m LootModel) Refresh() tea.Cmd {
	return func() tea.Msg {
		allLoot := loot.GetLootStore().All()
		rows := make(LootDataMsg, 0)
		if allLoot == nil {
			return rows
		}
		for _, l := range allLoot.Loot {
			fileType := "file"
			switch l.FileType {
			case 1:
				fileType = "binary"
			case 2:
				fileType = "text"
			}
			size := formatBytes(l.Size)
			rows = append(rows, LootRow{
				ID:   l.ID[:8],
				Name: l.Name,
				Type: fileType,
				Size: size,
			})
		}
		return rows
	}
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// View
// ─────────────────────────────────────────────────────────────────────────────

func (m LootModel) View(w, h int) string {
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#aa88ff"))
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaacc")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#555577"))
	text := lipgloss.NewStyle().Foreground(lipgloss.Color("#e0e0e0"))

	cols := []struct {
		h string
		w int
	}{
		{"ID", 10}, {"NAME", 40}, {"TYPE", 10}, {"SIZE", 12},
	}

	var b strings.Builder

	count := fmt.Sprintf("%d item(s)", len(m.Data))
	b.WriteString(purple.Bold(true).Render("Loot") + "  " + muted.Render(count) + "\n\n")

	if len(m.Data) == 0 {
		b.WriteString(muted.Render("  No loot collected yet.\n"))
		return b.String()
	}

	// Header
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
		line := purple.Render("◈") + " " +
			text.Width(cols[0].w-2).Render(l.ID) + " " +
			text.Width(cols[1].w).Render(l.Name) + " " +
			text.Width(cols[2].w).Render(l.Type) + " " +
			text.Width(cols[3].w).Render(l.Size)
		b.WriteString(line + "\n")
	}

	return b.String()
}
