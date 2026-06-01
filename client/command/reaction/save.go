package reaction

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
	"fmt"
	"os"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/client/core"
	"github.com/sudosoc/SUDOSOC-C2/client/forms"
	"github.com/spf13/cobra"
)

// ReactionSaveCmd - Manage reactions to events.
func ReactionSaveCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	reactionPath := GetReactionFilePath()
	if _, err := os.Stat(reactionPath); !os.IsNotExist(err) {
		confirm := false
		_ = forms.Confirm(fmt.Sprintf("Overwrite reactions (%s) on disk?", reactionPath), &confirm)
		if !confirm {
			return
		}
	}
	err := SaveReactions(core.Reactions.All())
	if err != nil {
		con.PrintErrorf("%s\n", err)
	} else {
		con.PrintInfof("Saved reactions to disk (%s)\n", reactionPath)
	}
}
