package wireguard

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
	"context"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/spf13/cobra"
)

// WGSocksStartCmd - Start a WireGuard reverse SOCKS proxy.
func WGSocksStartCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	if session.Transport != "wg" {
		con.PrintErrorf("This command is only supported for Wireguard implants")
		return
	}

	bindPort, _ := cmd.Flags().GetInt32("bind")

	socks, err := con.Rpc.WGStartSocks(context.Background(), &sudosocpb.WGSocksStartReq{
		Port:    int32(bindPort),
		Request: con.ActiveTarget.Request(cmd),
	})
	if err != nil {
		con.PrintErrorf("Error: %v", err)
		return
	}

	if socks.Response != nil && socks.Response.Err != "" {
		con.PrintErrorf("Error: %s\n", err)
		return
	}

	if socks.Server != nil {
		con.PrintInfof("Started SOCKS server on %s\n", socks.Server.LocalAddr)
	}
}
