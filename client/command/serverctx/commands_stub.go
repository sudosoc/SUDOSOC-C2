//go:build !client

package serverctx

import (
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/spf13/cobra"
)

// Commands is a no-op when building without the `client` build tag (e.g. sudosoc-server).
func Commands(_ *console.SudosocClient) []*cobra.Command {
	return nil
}
