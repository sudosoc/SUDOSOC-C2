package alias

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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sudosoc/SUDOSOC-C2/client/assets"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/client/forms"
	"github.com/spf13/cobra"
)

// AliasesRemoveCmd - Locally load a alias into the SUDOSOC-C2 shell.
func AliasesRemoveCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	name := args[0]
	// name := ctx.Args.String("name")
	if name == "" {
		con.PrintErrorf("Extension name is required\n")
		return
	}
	confirm := false
	_ = forms.Confirm(fmt.Sprintf("Remove '%s' alias?", name), &confirm)
	if !confirm {
		return
	}
	err := RemoveAliasByCommandName(name, con)
	if err != nil {
		con.PrintErrorf("Error removing alias: %s\n", err)
		return
	} else {
		con.PrintInfof("Alias '%s' removed\n", name)
	}
}

// RemoveAliasByCommandName - Remove an alias by command name.
func RemoveAliasByCommandName(commandName string, con *console.SudosocClient) error {
	if commandName == "" {
		return errors.New("command name is required")
	}
	if _, ok := loadedAliases[commandName]; !ok {
		return errors.New("alias not loaded")
	}
	delete(loadedAliases, commandName)
	// con.App.Commands().Remove(commandName)
	extPath := filepath.Join(assets.GetAliasesDir(), filepath.Base(commandName))
	if _, err := os.Stat(extPath); os.IsNotExist(err) {
		return nil
	}
	err := os.RemoveAll(extPath)
	if err != nil {
		return err
	}

	return nil
}
