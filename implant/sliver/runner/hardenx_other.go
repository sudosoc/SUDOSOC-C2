//go:build !linux && !darwin && !windows && !android

package runner

// Stub for unsupported platforms — no-op init() so the package compiles.
func init() {}
