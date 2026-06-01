package sessions

import (
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/spf13/cobra"
)

// BackgroundCmd - Background the active session.
func BackgroundCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	con.ActiveTarget.Background()
	con.PrintInfof("Background ...\n")
}
