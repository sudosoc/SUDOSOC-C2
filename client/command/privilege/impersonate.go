package privilege

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

	"google.golang.org/protobuf/proto"

	"github.com/spf13/cobra"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// ImpersonateCmd - Windows only, impersonate a user token
func ImpersonateCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		return
	}

	username := args[0]
	impersonate, err := con.Rpc.Impersonate(context.Background(), &sudosocpb.ImpersonateReq{
		Request:  con.ActiveTarget.Request(cmd),
		Username: username,
	})
	if err != nil {
		con.PrintErrorf("%s", err)
		return
	}

	if impersonate.Response != nil && impersonate.Response.Async {
		con.AddBeaconCallback(impersonate.Response.TaskID, func(task *clientpb.BeaconTask) {
			err = proto.Unmarshal(task.Response, impersonate)
			if err != nil {
				con.PrintErrorf("Failed to decode response %s\n", err)
				return
			}
			PrintImpersonate(impersonate, username, con)
		})
		con.PrintAsyncResponse(impersonate.Response)
	} else {
		PrintImpersonate(impersonate, username, con)
	}
}

// PrintImpersonate - Print the results of the attempted impersonation
func PrintImpersonate(impersonate *sudosocpb.Impersonate, username string, con *console.SudosocClient) {
	if impersonate.Response != nil && impersonate.Response.GetErr() != "" {
		con.PrintErrorf("%s\n", impersonate.Response.GetErr())
		return
	}
	con.PrintInfof("Successfully impersonated %s\n", username)
}
