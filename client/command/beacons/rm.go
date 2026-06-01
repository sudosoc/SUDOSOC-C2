package beacons

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
	"github.com/spf13/cobra"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
)

// BeaconsRmCmd - Display/interact with beacons
func BeaconsRmCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	beacon, err := SelectBeacon(con)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	grpcCtx, cancel := con.GrpcContext(cmd)
	defer cancel()
	_, err = con.Rpc.RmBeacon(grpcCtx, beacon)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	con.PrintInfof("Beacon removed (%s)\n", beacon.ID)
}
