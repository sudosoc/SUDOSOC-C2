//go:build windows

package cli

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
*/

// watchToggleSignal is a no-op on Windows because SIGUSR1 does not exist.
// On Windows, use the `ui start` / `ui stop` console commands instead,
// or launch with --ui to start the Web UI immediately.
func watchToggleSignal(_ uint16) {}
