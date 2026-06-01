package sessions

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
	"context"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/client/core"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/spf13/cobra"
)

// CloseSessionCmd - Close an interactive session but do not kill the remote process.
func CloseSessionCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	// Get the active session
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		con.PrintErrorf("No active session\n")
		return
	}

	// remove any active socks proxies
	socks := core.SocksProxies.List()
	if len(socks) != 0 {
		for _, p := range socks {
			if p.SessionID == session.ID {
				core.SocksProxies.Remove(p.ID)
			}
		}
	}

	// Close the session
	_, err := con.Rpc.CloseSession(context.Background(), &sudosocpb.CloseSession{
		Request: con.ActiveTarget.Request(cmd),
	})
	if err != nil {
		con.PrintErrorf("%s\n", err.Error())
		return
	}

	con.ActiveTarget.Set(nil, nil)
}
