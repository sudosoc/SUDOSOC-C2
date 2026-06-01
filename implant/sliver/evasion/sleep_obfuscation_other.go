//go:build !windows

package evasion

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Non-Windows fallback for ObfuscatedSleep.
//
// The image-encryption variant only exists for Windows today — Linux and
// macOS implants use a plain time.Sleep so the caller doesn't need build
// tags around every sleep site. The signature is kept identical to the
// Windows implementation so the beacon loop can call it unconditionally.
//
// A real Linux equivalent would need mprotect over the implant's PT_LOAD
// segments and a clock_nanosleep call that bypasses the Go scheduler
// (similar to SleepEx on Windows). That's a future enhancement, tracked
// separately from the initial Ekko/Foliage work.

import "time"

// ObfuscatedSleep mirrors the Windows implementation's signature and
// degrades to an unobfuscated time.Sleep on platforms where we haven't
// implemented memory hiding yet. encryptText is accepted for API parity
// but is meaningless here.
func ObfuscatedSleep(duration time.Duration, encryptText bool) error {
	_ = encryptText
	if duration > 0 {
		time.Sleep(duration)
	}
	return nil
}
