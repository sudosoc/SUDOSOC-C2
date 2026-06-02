//go:build !windows

package cli

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
*/

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sudosoc/SUDOSOC-C2/server/web"
)

// watchToggleSignal listens for SIGUSR1 and live-toggles the Web UI on/off.
// On Unix/macOS:  kill -USR1 $(pidof sudosoc-server)
func watchToggleSignal(uiPort uint16) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	go func() {
		for range sigs {
			active, port := web.Manager.Status()
			if active {
				_ = web.Manager.Stop()
				fmt.Printf("\n[sudosoc] Web UI stopped (was on :%d)\n", port)
			} else {
				if err := web.Manager.Start(uiPort); err != nil {
					fmt.Printf("\n[sudosoc] Web UI start failed: %v\n", err)
				} else {
					fmt.Printf("\n[sudosoc] Web UI started → http://localhost:%d\n", uiPort)
				}
			}
		}
	}()
}
