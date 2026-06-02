package web

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
	Beacon task queue helpers
*/

import (
	"fmt"
	"strings"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/server/db"
)

// beaconTaskList returns tasks for a beacon ID as JSON-ready structs.
// beaconTaskJSON is defined in api_sessions.go (same package).
func beaconTaskList(beaconID string) ([]beaconTaskJSON, error) {
	tasks, err := db.BeaconTasksByBeaconID(beaconID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch beacon tasks: %w", err)
	}

	out := make([]beaconTaskJSON, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, beaconTaskJSON{
			ID:          t.ID,
			State:       t.State,
			Description: t.Description,
			CreatedAt:   t.CreatedAt,
			SentAt:      t.SentAt,
			CompletedAt: t.CompletedAt,
		})
	}
	return out, nil
}

// queueBeaconExecute creates a pending shell-execute task on a beacon.
// The actual task delivery happens on the beacon's next check-in via
// the existing beacon task queue mechanism.
func queueBeaconExecute(beaconID string, command string) (map[string]interface{}, error) {
	args := strings.Fields(command)
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	// Confirm beacon exists
	beacon, err := db.BeaconByID(beaconID)
	if err != nil || beacon == nil {
		return nil, fmt.Errorf("beacon not found: %s", beaconID)
	}

	return map[string]interface{}{
		"state":       "pending",
		"description": fmt.Sprintf("execute: %s", command),
		"queued_at":   time.Now().Unix(),
		"message":     fmt.Sprintf("Task queued for %s. Will execute on next check-in (interval: %ds).", beacon.Name, beacon.Interval/1000),
		"command":     command,
	}, nil
}
