package aka

import (
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/spf13/cobra"
)

func AkaDeleteCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	aliasName := args[0]
	if _, exists := akaAliases[aliasName]; !exists {
		con.PrintErrorf("Alias '%s' does not exist\n", aliasName)
		return
	}

	delete(akaAliases, aliasName)

	// Save updated map to disk
	err := SaveAkaAliases()
	if err != nil {
		con.PrintErrorf("Failed to save aliases to disk: %s\n", err)
		return
	}

	con.PrintInfof("Deleted alias '%s'\n", aliasName)
}
