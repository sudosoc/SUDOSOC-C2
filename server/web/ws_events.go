package web

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
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	// Allow all origins for the local UI — restrict in production via mTLS.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// wsEvent is the JSON envelope sent to the browser over the events channel.
type wsEvent struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
	Time    int64       `json:"time"`
}

// handleWSEvents upgrades the connection and streams C2 events to the browser
// in real-time. The browser subscribes once and receives all session/beacon/
// operator state changes without polling.
func handleWSEvents(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Subscribe to the event broker.
	eventCh := core.EventBroker.Subscribe()
	defer core.EventBroker.Unsubscribe(eventCh)

	// Heartbeat ticker — keeps the connection alive and signals the UI that
	// the server is still up every 5 seconds.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				return
			}
			payload := map[string]interface{}{
				"event_type": event.EventType,
			}
			if event.Session != nil {
				payload["session_id"] = event.Session.ID
				payload["session_name"] = event.Session.Name
				payload["hostname"] = event.Session.Hostname
				payload["os"] = event.Session.OS
			}
			if event.Beacon != nil {
				payload["beacon_id"] = event.Beacon.ID.String()
				payload["beacon_name"] = event.Beacon.Name
			}
			if event.Client != nil {
				payload["operator"] = event.Client.Operator.Name
			}
			if event.Err != nil {
				payload["error"] = event.Err.Error()
			}

			env := wsEvent{
				Type:    event.EventType,
				Payload: payload,
				Time:    time.Now().Unix(),
			}
			data, err := json.Marshal(env)
			if err != nil {
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}

		case <-ticker.C:
			// Send a ping / heartbeat event so the UI knows the server is alive.
			ping := wsEvent{Type: "heartbeat", Time: time.Now().Unix()}
			data, _ := json.Marshal(ping)
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		}
	}
}
