package shell

import (
	"fmt"
	"strconv"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/rsteube/carapace"
)

// ShellIDCompleter completes IDs of managed local shells.
func ShellIDCompleter(_ *console.SudosocClient) carapace.Action {
	callback := func(_ carapace.Context) carapace.Action {
		results := make([]string, 0)

		managed := shells.List()
		if len(managed) == 0 {
			return carapace.ActionMessage("no managed shells")
		}

		for _, sh := range managed {
			results = append(results, strconv.Itoa(sh.ID))
			results = append(results, fmt.Sprintf("%s, pid=%d, state=%s", sessionLabel(sh.SessionID, sh.SessionName), sh.Pid, sh.State()))
		}

		return carapace.ActionValuesDescribed(results...).Tag("managed shells")
	}

	return carapace.ActionCallback(callback)
}
