package alias

import (
	"github.com/sudosoc/SUDOSOC-C2/client/command/completers"
	"github.com/sudosoc/SUDOSOC-C2/client/command/flags"
	"github.com/sudosoc/SUDOSOC-C2/client/command/help"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	consts "github.com/sudosoc/SUDOSOC-C2/client/constants"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
)

// Commands returns the `alias` command and its child commands.
func Commands(con *console.SudosocClient) []*cobra.Command {
	aliasCmd := &cobra.Command{
		Use:   consts.AliasesStr,
		Short: "List current aliases",
		Long:  help.GetHelpFor([]string{consts.AliasesStr}),
		Run: func(cmd *cobra.Command, args []string) {
			AliasesCmd(cmd, con, args)
		},
		GroupID: consts.GenericHelpGroup,
	}

	aliasLoadCmd := &cobra.Command{
		Use:   consts.LoadStr + " [ALIAS]",
		Short: "Load a command alias",
		Long:  help.GetHelpFor([]string{consts.AliasesStr, consts.LoadStr}),
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			AliasesLoadCmd(cmd, con, args)
		},
	}
	aliasCmd.AddCommand(aliasLoadCmd)
	flags.NewCompletions(aliasLoadCmd).PositionalCompletion(carapace.ActionDirectories().Tag("alias directory").Usage("path to the alias directory"))
	completers.RegisterLocalFilePathPositionalCompletion(aliasLoadCmd, 0)

	aliasInstallCmd := &cobra.Command{
		Use:   consts.InstallStr + " [ALIAS]",
		Short: "Install a command alias",
		Long:  help.GetHelpFor([]string{consts.AliasesStr, consts.InstallStr}),
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			AliasesInstallCmd(cmd, con, args)
		},
	}
	aliasCmd.AddCommand(aliasInstallCmd)
	flags.NewCompletions(aliasInstallCmd).PositionalCompletion(carapace.ActionFiles().Tag("alias file"))
	completers.RegisterLocalFilePathPositionalCompletion(aliasInstallCmd, 0)

	aliasRemove := &cobra.Command{
		Use:   consts.RmStr + " [ALIAS]",
		Short: "Remove an alias",
		Long:  help.GetHelpFor([]string{consts.RmStr}),
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			AliasesRemoveCmd(cmd, con, args)
		},
	}
	flags.NewCompletions(aliasRemove).PositionalCompletion(AliasCompleter())
	aliasCmd.AddCommand(aliasRemove)

	return []*cobra.Command{aliasCmd}
}
