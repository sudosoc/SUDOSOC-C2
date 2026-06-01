package handlers

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2021  Seif

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
	------------------------------------------------------------------------

	WARNING: These functions can be invoked by remote implants without user interaction

*/

import (
	"sync"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
)

type ServerHandler func(*core.ImplantConnection, []byte) *sudosocpb.Envelope

var (
	tunnelHandlerMutex = &sync.Mutex{}
)

// GetHandlers - Returns a map of server-side msg handlers
func GetHandlers() map[uint32]ServerHandler {
	return map[uint32]ServerHandler{
		// Sessions
		sudosocpb.MsgRegister:    registerSessionHandler,
		sudosocpb.MsgTunnelData:  tunnelDataHandler,
		sudosocpb.MsgTunnelClose: tunnelCloseHandler,
		sudosocpb.MsgPing:        pingHandler,
		sudosocpb.MsgSocksData:   socksDataHandler,

		// Beacons
		sudosocpb.MsgBeaconRegister: beaconRegisterHandler,
		sudosocpb.MsgBeaconTasks:    beaconTasksHandler,

		// Pivots
		sudosocpb.MsgPivotPeerEnvelope: pivotPeerEnvelopeHandler,
		sudosocpb.MsgPivotPeerFailure:  pivotPeerFailureHandler,
	}
}

// GetNonPivotHandlers - Server handlers for pivot connections, its important
// to avoid a pivot handler from calling a pivot handler and causing a recursive
// call stack
func GetNonPivotHandlers() map[uint32]ServerHandler {
	return map[uint32]ServerHandler{
		// Sessions
		sudosocpb.MsgRegister:    registerSessionHandler,
		sudosocpb.MsgTunnelData:  tunnelDataHandler,
		sudosocpb.MsgTunnelClose: tunnelCloseHandler,
		sudosocpb.MsgPing:        pingHandler,
		sudosocpb.MsgSocksData:   socksDataHandler,

		// Beacons - Not currently supported in pivots
	}
}
