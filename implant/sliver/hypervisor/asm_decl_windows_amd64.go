//go:build windows && amd64

package hypervisor

// Assembly declarations for VT-x hypervisor operations.
// Implementations are in hypervisor_windows_amd64.s

func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)
func rdmsr(msr uint32) uint64
func wrmsr(msr uint32, val uint64)
func getCR0() uint64
func getCR3() uint64
func getCR4() uint64
func setCR0(val uint64)
func setCR4(val uint64)
func getGDTR() (base uint64, limit uint16)
func getIDTR() (base uint64, limit uint16)
func getCS() uint16
func getSS() uint16
func getDS() uint16
func getES() uint16
func getFS() uint16
func getGS() uint16
func getTR() uint16
func getLDTR() uint16
func getRFLAGS() uint64
func vmxon(physAddr uint64) uint8
func vmxoff()
func vmclear(physAddr uint64) uint8
func vmptrld(physAddr uint64) uint8
func vmwrite(field, value uint64) uint8
func vmread(field uint64) (uint64, uint8)
func vmlaunch() uint8
func vmresume() uint8
func invept(invType uint64, eptp uint64)
func invvpid(invType uint64, vpid uint16, gva uint64)
func vmExitTrampoline()
