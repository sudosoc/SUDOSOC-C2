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

// Non-Windows stub — ETW and AMSI are Windows-only subsystems.

// ETWPatchResult mirrors the Windows type for cross-platform callers.
type ETWPatchResult struct {
	Patched []string
	Failed  map[string]error
}

// PatchETW is a no-op on non-Windows platforms.
func PatchETW() (*ETWPatchResult, error) {
	return &ETWPatchResult{Failed: make(map[string]error)}, nil
}

// PatchAMSI is a no-op on non-Windows platforms.
func PatchAMSI() error { return nil }
