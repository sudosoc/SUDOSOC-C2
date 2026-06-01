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

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/handlers/tunnel_handlers"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

var (
	tunnelHandlers = map[uint32]TunnelHandler{

		// Interactive shell tunnels
		sudosocpb.MsgShellReq:       tunnel_handlers.ShellReqHandler,
		sudosocpb.MsgShellResizeReq: tunnel_handlers.ShellResizeReqHandler,

		// Network tunnels
		sudosocpb.MsgPortfwdReq: tunnel_handlers.PortfwdReqHandler,
		sudosocpb.MsgSocksData:  tunnel_handlers.SocksReqHandler,

		// Wasm Extensions can be  executed interactively
		sudosocpb.MsgExecWasmExtensionReq: tunnel_handlers.ExecWasmExtensionHandler,

		// Data and close messages
		sudosocpb.MsgTunnelData:  tunnel_handlers.TunnelDataHandler,
		sudosocpb.MsgTunnelClose: tunnel_handlers.TunnelCloseHandler,
	}
)

// GetTunnelHandlers - Returns a map of tunnel handlers
func GetTunnelHandlers() map[uint32]TunnelHandler {
	// {{if .Config.Debug}}
	log.Printf("[tunnel] Tunnel handlers %v", tunnelHandlers)
	// {{end}}
	return tunnelHandlers
}
