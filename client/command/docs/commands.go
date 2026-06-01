package docs

import (
	"github.com/sudosoc/SUDOSOC-C2/client/command/help"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	consts "github.com/sudosoc/SUDOSOC-C2/client/constants"
	"github.com/spf13/cobra"
)

// Commands returns the docs command.
func Commands(con *console.SudosocClient) []*cobra.Command {
	return []*cobra.Command{newDocsCommand(consts.SudosocCoreHelpGroup, con)}
}

// ServerCommands returns the docs command for the top-level client REPL.
func ServerCommands(con *console.SudosocClient) []*cobra.Command {
	return []*cobra.Command{newDocsCommand(consts.GenericHelpGroup, con)}
}

func newDocsCommand(groupID string, con *console.SudosocClient) *cobra.Command {
	return &cobra.Command{
		Use:     consts.DocsStr,
		Short:   "Browse the embedded Sliver docs in a TUI",
		Long:    help.GetHelpFor([]string{consts.DocsStr}),
		Args:    cobra.NoArgs,
		GroupID: groupID,
		Run: func(cmd *cobra.Command, args []string) {
			DocsCmd(cmd, con, args)
		},
	}
}
