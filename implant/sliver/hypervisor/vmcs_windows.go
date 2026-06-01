package hypervisor

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	VMCS (Virtual Machine Control Structure) field encodings and setup.

	Every VMCS field is identified by a 16-bit encoding used with VMREAD/VMWRITE.
	Encodings are divided into four access widths (16, 32, 64, natural-width)
	and three field types (control, guest-state, host-state).

	Reference: Intel SDM Vol. 3C, Appendix B.
*/

// ─── VMCS 16-bit Control Fields ───────────────────────────────────────────
const (
	VmcsVpid                    = 0x0000
	VmcsPostedIntNotifVector    = 0x0002
	VmcsEptpIndex               = 0x0004
)

// ─── VMCS 16-bit Guest-State Fields ───────────────────────────────────────
const (
	VmcsGuestEsSelector         = 0x0800
	VmcsGuestCsSelector         = 0x0802
	VmcsGuestSsSelector         = 0x0804
	VmcsGuestDsSelector         = 0x0806
	VmcsGuestFsSelector         = 0x0808
	VmcsGuestGsSelector         = 0x080A
	VmcsGuestLdtrSelector       = 0x080C
	VmcsGuestTrSelector         = 0x080E
	VmcsGuestInterruptStatus    = 0x0810
)

// ─── VMCS 16-bit Host-State Fields ────────────────────────────────────────
const (
	VmcsHostEsSelector          = 0x0C00
	VmcsHostCsSelector          = 0x0C02
	VmcsHostSsSelector          = 0x0C04
	VmcsHostDsSelector          = 0x0C06
	VmcsHostFsSelector          = 0x0C08
	VmcsHostGsSelector          = 0x0C0A
	VmcsHostTrSelector          = 0x0C0C
)

// ─── VMCS 64-bit Control Fields ───────────────────────────────────────────
const (
	VmcsIoBitmapA               = 0x2000
	VmcsIoBitmapB               = 0x2002
	VmcsMsrBitmap               = 0x2004
	VmcsVmExitMsrStoreAddr      = 0x2006
	VmcsVmExitMsrLoadAddr       = 0x2008
	VmcsVmEntryMsrLoadAddr      = 0x200A
	VmcsExecutiveVmcsPtr        = 0x200C
	VmcsTscOffset               = 0x2010
	VmcsVirtualApicAddr         = 0x2012
	VmcsApicAccessAddr          = 0x2014
	VmcsEptPointer              = 0x201A
)

// ─── VMCS 64-bit Guest-State Fields ───────────────────────────────────────
const (
	VmcsGuestPhysAddr           = 0x2400
	VmcsVmcsLinkPtr             = 0x2800
	VmcsGuestIa32Debugctl       = 0x2802
	VmcsGuestIa32Pat            = 0x2804
	VmcsGuestIa32Efer           = 0x2806
	VmcsGuestIa32PerfGlobalCtrl = 0x2808
	VmcsGuestPdpte0             = 0x280A
	VmcsGuestPdpte1             = 0x280C
	VmcsGuestPdpte2             = 0x280E
	VmcsGuestPdpte3             = 0x2810
)

// ─── VMCS 64-bit Host-State Fields ────────────────────────────────────────
const (
	VmcsHostIa32Pat             = 0x2C00
	VmcsHostIa32Efer            = 0x2C02
	VmcsHostIa32PerfGlobalCtrl  = 0x2C04
)

// ─── VMCS 32-bit Control Fields ───────────────────────────────────────────
const (
	VmcsPinBasedVmExecControl   = 0x4000
	VmcsCpuBasedVmExecControl   = 0x4002
	VmcsExceptionBitmap         = 0x4004
	VmcsPageFaultErrCodeMask    = 0x4006
	VmcsPageFaultErrCodeMatch   = 0x4008
	VmcsCr3TargetCount          = 0x400A
	VmcsVmExitControls          = 0x400C
	VmcsVmExitMsrStoreCount     = 0x400E
	VmcsVmExitMsrLoadCount      = 0x4010
	VmcsVmEntryControls         = 0x4012
	VmcsVmEntryMsrLoadCount     = 0x4014
	VmcsVmEntryIntrInfoField    = 0x4016
	VmcsVmEntryExcErrCode       = 0x4018
	VmcsVmEntryInstrLen         = 0x401A
	VmcsTprThreshold            = 0x401C
	VmcsSecondaryVmExecControl  = 0x401E
	VmcsPleGap                  = 0x4020
	VmcsPleWindow               = 0x4022
)

// ─── VMCS 32-bit Guest-State Fields ───────────────────────────────────────
const (
	VmcsGuestEsLimit            = 0x4800
	VmcsGuestCsLimit            = 0x4802
	VmcsGuestSsLimit            = 0x4804
	VmcsGuestDsLimit            = 0x4806
	VmcsGuestFsLimit            = 0x4808
	VmcsGuestGsLimit            = 0x480A
	VmcsGuestLdtrLimit          = 0x480C
	VmcsGuestTrLimit            = 0x480E
	VmcsGuestGdtrLimit          = 0x4810
	VmcsGuestIdtrLimit          = 0x4812
	VmcsGuestEsAccessRights     = 0x4814
	VmcsGuestCsAccessRights     = 0x4816
	VmcsGuestSsAccessRights     = 0x4818
	VmcsGuestDsAccessRights     = 0x481A
	VmcsGuestFsAccessRights     = 0x481C
	VmcsGuestGsAccessRights     = 0x481E
	VmcsGuestLdtrAccessRights   = 0x4820
	VmcsGuestTrAccessRights     = 0x4822
	VmcsGuestInterruptibililty  = 0x4824
	VmcsGuestActivityState      = 0x4826
	VmcsGuestSysenterCs         = 0x482A
	VmcsVmxPreemptionTimerValue = 0x482E
)

// ─── VMCS 32-bit Host-State Fields ────────────────────────────────────────
const (
	VmcsHostIa32SysenterCs      = 0x4C00
)

// ─── VMCS Natural-Width Control Fields ────────────────────────────────────
const (
	VmcsCr0GuestHostMask        = 0x6000
	VmcsCr4GuestHostMask        = 0x6002
	VmcsCr0ReadShadow           = 0x6004
	VmcsCr4ReadShadow           = 0x6006
	VmcsCr3TargetValue0         = 0x6008
	VmcsCr3TargetValue1         = 0x600A
	VmcsCr3TargetValue2         = 0x600C
	VmcsCr3TargetValue3         = 0x600E
)

// ─── VMCS Natural-Width Read-Only Fields ──────────────────────────────────
const (
	VmcsExitQualification       = 0x6400
	VmcsIoRcx                   = 0x6402
	VmcsIoRsi                   = 0x6404
	VmcsIoRdi                   = 0x6406
	VmcsIoRip                   = 0x6408
	VmcsGuestLinearAddr         = 0x640A
)

// ─── VMCS Natural-Width Guest-State Fields ────────────────────────────────
const (
	VmcsGuestCr0                = 0x6800
	VmcsGuestCr3                = 0x6802
	VmcsGuestCr4                = 0x6804
	VmcsGuestEsBase             = 0x6806
	VmcsGuestCsBase             = 0x6808
	VmcsGuestSsBase             = 0x680A
	VmcsGuestDsBase             = 0x680C
	VmcsGuestFsBase             = 0x680E
	VmcsGuestGsBase             = 0x6810
	VmcsGuestLdtrBase           = 0x6812
	VmcsGuestTrBase             = 0x6814
	VmcsGuestGdtrBase           = 0x6816
	VmcsGuestIdtrBase           = 0x6818
	VmcsGuestDr7                = 0x681A
	VmcsGuestRsp                = 0x681C
	VmcsGuestRip                = 0x681E
	VmcsGuestRflags             = 0x6820
	VmcsGuestPendingDbgExc      = 0x6822
	VmcsGuestSysenterEsp        = 0x6824
	VmcsGuestSysenterEip        = 0x6826
)

// ─── VMCS Natural-Width Host-State Fields ─────────────────────────────────
const (
	VmcsHostCr0                 = 0x6C00
	VmcsHostCr3                 = 0x6C02
	VmcsHostCr4                 = 0x6C04
	VmcsHostFsBase              = 0x6C06
	VmcsHostGsBase              = 0x6C08
	VmcsHostTrBase              = 0x6C0A
	VmcsHostGdtrBase            = 0x6C0C
	VmcsHostIdtrBase            = 0x6C0E
	VmcsHostIa32SysenterEsp     = 0x6C10
	VmcsHostIa32SysenterEip     = 0x6C12
	VmcsHostRsp                 = 0x6C14
	VmcsHostRip                 = 0x6C16
)

// ─── Pin-Based VM-Execution Control Bits ─────────────────────────────────
const (
	PinBasedExtIntExiting       = 1 << 0
	PinBasedNmiExiting          = 1 << 3
	PinBasedVirtualNmis         = 1 << 5
	PinBasedVmxPreemptionTimer  = 1 << 6
	PinBasedPostedInterrupts    = 1 << 7
)

// ─── Primary Processor-Based VM-Execution Control Bits ───────────────────
const (
	CpuBasedIntWindowExiting    = 1 << 2
	CpuBasedTscOffsetting       = 1 << 3
	CpuBasedHltExiting          = 1 << 7
	CpuBasedInvlpgExiting       = 1 << 9
	CpuBasedMwaitExiting        = 1 << 10
	CpuBasedRdpmcExiting        = 1 << 11
	CpuBasedRdtscExiting        = 1 << 12
	CpuBasedCr3LoadExiting      = 1 << 15
	CpuBasedCr3StoreExiting     = 1 << 16
	CpuBasedCr8LoadExiting      = 1 << 19
	CpuBasedCr8StoreExiting     = 1 << 20
	CpuBasedTprShadow           = 1 << 21
	CpuBasedNmiWindowExiting    = 1 << 22
	CpuBasedMovDrExiting        = 1 << 23
	CpuBasedUnconditionalIoExiting = 1 << 24
	CpuBasedUseIoBitmaps        = 1 << 25
	CpuBasedMonitorTrapFlag     = 1 << 27
	CpuBasedUseMsrBitmaps       = 1 << 28
	CpuBasedMonitorExiting      = 1 << 29
	CpuBasedPauseExiting        = 1 << 30
	CpuBasedActivateSecondaryControls = 1 << 31
)

// ─── Secondary Processor-Based VM-Execution Control Bits ─────────────────
const (
	SecondaryExecVirtualizeApic = 1 << 0
	SecondaryExecEnableEpt      = 1 << 1
	SecondaryExecDescriptorTableExiting = 1 << 2
	SecondaryExecEnableRdtscp   = 1 << 3
	SecondaryExecVirtualizeX2Apic = 1 << 4
	SecondaryExecEnableVpid     = 1 << 5
	SecondaryExecWbinvdExiting  = 1 << 6
	SecondaryExecUnrestrictedGuest = 1 << 7
	SecondaryExecEnableInvpcid  = 1 << 12
	SecondaryExecEnableXsaves   = 1 << 20
)

// ─── VM-Exit Control Bits ─────────────────────────────────────────────────
const (
	VmExitSaveDebugControls     = 1 << 2
	VmExitHostAddrSpaceSize     = 1 << 9
	VmExitLoadIa32Pat           = 1 << 18
	VmExitSaveIa32Efer          = 1 << 20
	VmExitLoadIa32Efer          = 1 << 21
)

// ─── VM-Entry Control Bits ────────────────────────────────────────────────
const (
	VmEntryLoadDebugControls    = 1 << 2
	VmEntryIa32eModeGuest       = 1 << 9
	VmEntryLoadIa32Pat          = 1 << 14
	VmEntryLoadIa32Efer         = 1 << 15
)

// ─── VM-Exit Reasons ─────────────────────────────────────────────────────
const (
	ExitReasonExceptionNmi      = 0
	ExitReasonExternalInterrupt = 1
	ExitReasonTripleFault       = 2
	ExitReasonCpuid             = 10
	ExitReasonHlt               = 12
	ExitReasonInvd              = 13
	ExitReasonInvlpg            = 14
	ExitReasonRdmsr             = 31
	ExitReasonWrmsr             = 32
	ExitReasonVmcall            = 18
	ExitReasonCrAccess          = 28
	ExitReasonIoInstruction     = 30
	ExitReasonEptViolation      = 48
	ExitReasonVmxPreemptionTimeout = 52
)

// ─── MSR Numbers ─────────────────────────────────────────────────────────
const (
	MsrIa32FeatureControl       = 0x0000003A
	MsrIa32VmxBasic             = 0x00000480
	MsrIa32VmxPinbasedCtls      = 0x00000481
	MsrIa32VmxProcbasedCtls     = 0x00000482
	MsrIa32VmxExitCtls          = 0x00000483
	MsrIa32VmxEntryCtls         = 0x00000484
	MsrIa32VmxCr0Fixed0         = 0x00000486
	MsrIa32VmxCr0Fixed1         = 0x00000487
	MsrIa32VmxCr4Fixed0         = 0x00000488
	MsrIa32VmxCr4Fixed1         = 0x00000489
	MsrIa32VmxProcbasedCtls2    = 0x0000048B
	MsrIa32Efer                 = 0xC0000080
	MsrIa32Star                 = 0xC0000081
	MsrIa32Lstar                = 0xC0000082
	MsrIa32FsBase               = 0xC0000100
	MsrIa32GsBase               = 0xC0000101
	MsrIa32KernelGsBase         = 0xC0000102
	MsrIa32SysenterCs           = 0x00000174
	MsrIa32SysenterEsp          = 0x00000175
	MsrIa32SysenterEip          = 0x00000176
	MsrIa32Debugctl             = 0x000001D9
	MsrIa32Pat                  = 0x00000277
)

// ─── Segment Access Rights (AR bytes) ────────────────────────────────────
const (
	SegAccessPresent            = 1 << 7
	SegAccessDpl0               = 0 << 5
	SegAccessDpl3               = 3 << 5
	SegAccessCodeSegment        = 0x18  // code, exec/read
	SegAccessDataSegment        = 0x12  // data, read/write
	SegAccessTssSegment         = 0x0B  // TSS, 64-bit busy
	SegAccessLdtSegment         = 0x02  // LDT
	SegAccessLongMode           = 1 << 13
	SegAccessDefaultOp          = 1 << 14
	SegAccessGranularity        = 1 << 15
)

// GuestSegmentAR constructs the access-rights DWORD for a 64-bit code/data segment.
func GuestCodeSegmentAR() uint32 {
	return SegAccessPresent | SegAccessCodeSegment | SegAccessLongMode | SegAccessDpl0
}
func GuestDataSegmentAR() uint32 {
	return SegAccessPresent | SegAccessDataSegment | SegAccessDpl0
}
func GuestTSSAR() uint32 {
	return SegAccessPresent | SegAccessTssSegment | SegAccessDpl0
}
func UnusableSegmentAR() uint32 {
	return 1 << 16 // unusable
}
