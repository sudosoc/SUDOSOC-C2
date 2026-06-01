package jobs

import (
	"testing"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	consts "github.com/sudosoc/SUDOSOC-C2/client/constants"
	"github.com/spf13/cobra"
)

func TestHTTPAndHTTPSWebsiteFlagCompletionRegistered(t *testing.T) {
	cmds := Commands(&console.SudosocClient{})

	httpCmd := commandByUse(cmds, consts.HttpStr)
	if httpCmd == nil {
		t.Fatalf("missing %q command", consts.HttpStr)
	}
	if _, ok := httpCmd.GetFlagCompletionFunc("website"); !ok {
		t.Fatalf("%q missing website flag completion func", consts.HttpStr)
	}

	httpsCmd := commandByUse(cmds, consts.HttpsStr)
	if httpsCmd == nil {
		t.Fatalf("missing %q command", consts.HttpsStr)
	}
	if _, ok := httpsCmd.GetFlagCompletionFunc("website"); !ok {
		t.Fatalf("%q missing website flag completion func", consts.HttpsStr)
	}
}

func commandByUse(cmds []*cobra.Command, use string) *cobra.Command {
	for _, cmd := range cmds {
		if cmd.Use == use {
			return cmd
		}
	}
	return nil
}
