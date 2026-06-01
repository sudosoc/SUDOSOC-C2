//go:build !windows

package evasion

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Non-Windows stub — stack spoofing relies on x64 Windows ABI and ntdll.
*/

// SpoofedWait is a no-op on non-Windows platforms.
func SpoofedWait(_ uint32) {}

// getCurrentRSP stub for non-amd64/non-windows builds.
func getCurrentRSP() uintptr { return 0 }
