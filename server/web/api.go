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

	"github.com/gorilla/mux"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
	"github.com/sudosoc/SUDOSOC-C2/server/loot"
)

// ─────────────────────────────────────────────────────────────────────────────
// /api/stats
// ─────────────────────────────────────────────────────────────────────────────

type statsResponse struct {
	Sessions  int    `json:"sessions"`
	Beacons   int    `json:"beacons"`
	Listeners int    `json:"listeners"`
	Operators int    `json:"operators"`
	Uptime    string `json:"uptime"`
}

var serverStart = time.Now()

func handleStats(w http.ResponseWriter, r *http.Request) {
	sessions := core.Sessions.All()
	beacons, _ := db.ListBeacons()
	listeners := core.Jobs.All()
	operators := core.Clients.ActiveOperators()

	resp := statsResponse{
		Sessions:  len(sessions),
		Beacons:   len(beacons),
		Listeners: len(listeners),
		Operators: len(operators),
		Uptime:    time.Since(serverStart).Round(time.Second).String(),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ─────────────────────────────────────────────────────────────────────────────
// /api/sessions
// ─────────────────────────────────────────────────────────────────────────────

type sessionJSON struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	Username      string `json:"username"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Transport     string `json:"transport"`
	RemoteAddress string `json:"remote_address"`
	PID           int32  `json:"pid"`
	LastCheckin   int64  `json:"last_checkin"`
	IsDead        bool   `json:"is_dead"`
	ActiveC2      string `json:"active_c2"`
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	all := core.Sessions.All()
	out := make([]sessionJSON, 0, len(all))
	for _, s := range all {
		out = append(out, sessionJSON{
			ID:            s.ID,
			Name:          s.Name,
			Hostname:      s.Hostname,
			Username:      s.Username,
			OS:            s.OS,
			Arch:          s.Arch,
			Transport:     s.Connection.Transport,
			RemoteAddress: s.Connection.RemoteAddress,
			PID:           s.PID,
			LastCheckin:   s.LastCheckin().Unix(),
			IsDead:        s.IsDead(),
			ActiveC2:      s.ActiveC2,
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func handleSessionKill(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	session := core.Sessions.Get(id)
	if session == nil {
		jsonError(w, "session not found", http.StatusNotFound)
		return
	}
	core.Sessions.Remove(session.ID)
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────────────────────────────────────────────────────────
// /api/beacons
// ─────────────────────────────────────────────────────────────────────────────

type beaconJSON struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	Username      string `json:"username"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Transport     string `json:"transport"`
	RemoteAddress string `json:"remote_address"`
	LastCheckin   int64  `json:"last_checkin"`
	NextCheckin   int64  `json:"next_checkin"`
	Interval      int64  `json:"interval"`
	ActiveC2      string `json:"active_c2"`
}

func handleBeacons(w http.ResponseWriter, r *http.Request) {
	beacons, err := db.ListBeacons()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]beaconJSON, 0, len(beacons))
	for _, b := range beacons {
		out = append(out, beaconJSON{
			ID:            b.ID,
			Name:          b.Name,
			Hostname:      b.Hostname,
			Username:      b.Username,
			OS:            b.OS,
			Arch:          b.Arch,
			Transport:     b.Transport,
			RemoteAddress: b.RemoteAddress,
			LastCheckin:   b.LastCheckin,
			NextCheckin:   b.NextCheckin,
			Interval:      b.Interval,
			ActiveC2:      b.ActiveC2,
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// /api/listeners
// ─────────────────────────────────────────────────────────────────────────────

type listenerJSON struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Protocol string   `json:"protocol"`
	Port     uint16   `json:"port"`
	Domains  []string `json:"domains,omitempty"`
}

func handleListeners(w http.ResponseWriter, r *http.Request) {
	all := core.Jobs.All()
	out := make([]listenerJSON, 0, len(all))
	for _, j := range all {
		// j.Protocol is the transport layer ("tcp", "udp") — not what the UI wants.
		// j.Name is the application-layer protocol ("mtls", "http", "https", "dns", "wg").
		out = append(out, listenerJSON{
			ID:       j.ID,
			Name:     j.Name,
			Protocol: j.Name,   // use Name (mtls/http/https/dns/wg) not Protocol (tcp/udp)
			Port:     j.Port,
			Domains:  j.Domains,
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// /api/loot
// ─────────────────────────────────────────────────────────────────────────────

type lootJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FileType int32  `json:"file_type"`
	Size     int64  `json:"size"`
}

func handleLoot(w http.ResponseWriter, r *http.Request) {
	allLoot := loot.GetLootStore().All()
	out := make([]lootJSON, 0)
	if allLoot != nil {
		for _, l := range allLoot.Loot {
			out = append(out, lootJSON{
				ID:       l.ID,
				Name:     l.Name,
				FileType: int32(l.FileType),
				Size:     l.Size,
			})
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// /api/operators
// ─────────────────────────────────────────────────────────────────────────────

type operatorJSON struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

func handleOperators(w http.ResponseWriter, r *http.Request) {
	names := core.Clients.ActiveOperators()
	out := make([]operatorJSON, 0, len(names))
	for _, name := range names {
		out = append(out, operatorJSON{Name: name, Online: true})
	}
	_ = json.NewEncoder(w).Encode(out)
}
