//go:build !windows

package handlers

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2019  Seif

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
	"os"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"google.golang.org/protobuf/proto"
)

var killHandlers = map[uint32]KillHandler{
	sudosocpb.MsgKillSessionReq: killHandler,
}

// GetKillHandlers returns the specialHandlers map
func GetKillHandlers() map[uint32]KillHandler {
	return killHandlers
}

func killHandler(data []byte, _ *transports.Connection) error {
	killReq := &sudosocpb.KillReq{}
	err := proto.Unmarshal(data, killReq)
	// {{if .Config.Debug}}
	log.Println("KILL called")
	// {{end}}
	if err != nil {
		return err
	}
	// {{if .Config.Debug}}
	log.Println("Let's exit!")
	// {{end}}
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
	return nil
}
