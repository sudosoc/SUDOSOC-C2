package mcp

import (
	"context"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	clientmcp "github.com/sudosoc/SUDOSOC-C2/client/mcp"
	"github.com/spf13/cobra"
)

const mcpStopTimeout = 5 * time.Second

// McpStopCmd stops the local MCP server.
func McpStopCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), mcpStopTimeout)
	defer cancel()

	if err := clientmcp.Stop(ctx); err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	con.PrintInfof("MCP server stopped\n")
}
