//go:build !server

// This stub satisfies the assetsFs reference when building without -tags server.
// The real embedded filesystem is in assets_<os>_<arch>.go files which require -tags server.

package assets

import "embed"

// assetsFs is a placeholder for non-server builds.
// Real asset embedding requires: go build -tags server
//
//go:embed fs/empty.txt
var assetsFs embed.FS
