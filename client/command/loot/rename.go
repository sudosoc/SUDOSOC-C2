package loot

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

	"github.com/spf13/cobra"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/client/forms"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
)

// LootRenameCmd - Rename a piece of loot
func LootRenameCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	loot, err := SelectLoot(cmd, con.Rpc)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	oldName := loot.Name
	newName := ""
	_ = forms.Input("Enter new name:", &newName)

	loot, err = con.Rpc.LootUpdate(context.Background(), &clientpb.Loot{
		ID:   loot.ID,
		Name: newName,
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	con.PrintInfof("Renamed %s -> %s\n", oldName, loot.Name)
}
