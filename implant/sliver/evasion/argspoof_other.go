//go:build !windows

package evasion

// SpoofCommandLine is a no-op on non-Windows platforms.
func SpoofCommandLine(_ string) (uintptr, error) { return 0, nil }

// RestoreCommandLine is a no-op on non-Windows platforms.
func RestoreCommandLine(_ uintptr) {}

// SpoofImagePathName is a no-op on non-Windows platforms.
func SpoofImagePathName(_ string) error { return nil }

// SpawnWithSpoofedParent is a no-op on non-Windows platforms.
func SpawnWithSpoofedParent(_, _ string, _ uint32) (uint32, error) { return 0, nil }
