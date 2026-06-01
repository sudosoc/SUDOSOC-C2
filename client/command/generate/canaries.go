package generate

import (
	"context"
	"fmt"

	"github.com/sudosoc/SUDOSOC-C2/client/command/settings"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// CanariesCmd - Display canaries from the database and their status.
func CanariesCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	canaries, err := con.Rpc.Canaries(context.Background(), &commonpb.Empty{})
	if err != nil {
		con.PrintErrorf("Failed to list canaries %s", err)
		return
	}
	if 0 < len(canaries.Canaries) {
		burnedOnly, _ := cmd.Flags().GetBool("burned")
		PrintCanaries(con, canaries.Canaries, burnedOnly)
	} else {
		con.PrintInfof("No canaries in database\n")
	}
}

// PrintCanaries - Print the canaries tracked by the server.
func PrintCanaries(con *console.SudosocClient, canaries []*clientpb.DNSCanary, burnedOnly bool) {
	tw := table.NewWriter()
	tw.SetStyle(settings.GetTableStyle(con))
	tw.AppendHeader(table.Row{
		"Implant Name",
		"Domain",
		"Triggered",
		"First Trigger",
		"Latest Trigger",
	})
	for _, canary := range canaries {
		if burnedOnly && !canary.Triggered {
			continue
		}
		lineStyle := console.StyleNormal
		if canary.Triggered {
			lineStyle = console.StyleBoldRed
		}
		firstTrigger := "Never"
		latestTrigger := "Never"
		if canary.Triggered {
			firstTrigger = lineStyle.Render(canary.FirstTriggered)
			latestTrigger = lineStyle.Render(canary.LatestTrigger)
		}
		row := table.Row{
			lineStyle.Render(canary.ImplantName),
			lineStyle.Render(canary.Domain),
			lineStyle.Render(fmt.Sprintf("%v", canary.Triggered)),
			firstTrigger,
			latestTrigger,
		}
		tw.AppendRow(row)
	}
	con.Printf("%s\n", tw.Render())
}
