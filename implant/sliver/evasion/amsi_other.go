//go:build !windows

package evasion

// AMSIBypassResult mirrors the Windows type for cross-platform callers.
type AMSIBypassResult struct {
	StubPatch   bool
	CtxCorrupt  bool
	RegistryCLM bool
	SBLDisabled bool
}

// BypassAMSI is a no-op on non-Windows platforms.
func BypassAMSI() *AMSIBypassResult { return &AMSIBypassResult{} }
