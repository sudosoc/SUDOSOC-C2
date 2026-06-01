package rportfwd

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
	"context"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/spf13/cobra"
)

// StartRportFwdListenerCmd - Start listener for reverse port forwarding on implant.
func StopRportFwdListenerCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}

	listenerID, _ := cmd.Flags().GetUint32("id")
	rportfwdListener, err := con.Rpc.StopRportFwdListener(context.Background(), &sudosocpb.RportFwdStopListenerReq{
		Request: con.ActiveTarget.Request(cmd),
		ID:      listenerID,
	})
	if err != nil {
		con.PrintWarnf("%s\n", err)
		return
	}
	printStoppedRportFwdListener(rportfwdListener, con)
}

func printStoppedRportFwdListener(rportfwdListener *sudosocpb.RportFwdListener, con *console.SudosocClient) {
	if rportfwdListener.Response != nil && rportfwdListener.Response.Err != "" {
		con.PrintErrorf("%s", rportfwdListener.Response.Err)
		return
	}
	con.PrintInfof("Stopped reverse port forwarding %s <- %s\n", rportfwdListener.ForwardAddress, rportfwdListener.BindAddress)
}
