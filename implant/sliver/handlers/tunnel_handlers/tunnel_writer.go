package tunnel_handlers

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2022  Seif

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

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"google.golang.org/protobuf/proto"
)

// tunnelWriter - Sends data back to the server based on data read()
// I know the reader/writer stuff is a little hard to keep track of
type tunnelWriter struct {
	tun  *transports.Tunnel
	conn *transports.Connection
}

func (tw tunnelWriter) Write(data []byte) (int, error) {
	n := len(data)
	data, err := proto.Marshal(&sudosocpb.TunnelData{
		Sequence: tw.tun.WriteSequence(), // The tunnel write sequence
		Ack:      tw.tun.ReadSequence(),
		TunnelID: tw.tun.ID,
		Data:     data,
	})
	// {{if .Config.Debug}}
	log.Printf("[tunnelWriter] Write %d bytes (write seq: %d) ack: %d", n, tw.tun.WriteSequence(), tw.tun.ReadSequence())
	// {{end}}
	tw.tun.IncWriteSequence() // Increment write sequence
	tw.conn.Send <- &sudosocpb.Envelope{
		Type: sudosocpb.MsgTunnelData,
		Data: data,
	}
	return n, err
}
