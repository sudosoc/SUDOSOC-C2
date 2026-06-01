package hexedit

import (
	"github.com/sudosoc/SUDOSOC-C2/client/command/flags"
	"github.com/sudosoc/SUDOSOC-C2/client/command/help"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	consts "github.com/sudosoc/SUDOSOC-C2/client/constants"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Commands returns the hex-edit command.
func Commands(con *console.SudosocClient) []*cobra.Command {
	hexEditCmd := &cobra.Command{
		Use:     consts.HexEditStr + " <remote path>",
		Short:   "Hex edit a remote file",
		Long:    help.GetHelpFor([]string{consts.HexEditStr}),
		Args:    cobra.ExactArgs(1),
		GroupID: consts.FilesystemHelpGroup,
		Run: func(cmd *cobra.Command, args []string) {
			HexEditCmd(cmd, con, args)
		},
	}

	flags.Bind("", false, hexEditCmd, func(f *pflag.FlagSet) {
		f.String("max-size", "8MB", "maximum file size to load (e.g. 8MB, 512KB)")
		f.Int64("offset", 0, "byte offset to jump to (decimal or 0x...)")
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})

	carapace.Gen(hexEditCmd).PositionalCompletion(
		carapace.ActionValues().Usage("path to the remote file to hex edit"),
	)

	return []*cobra.Command{hexEditCmd}
}
