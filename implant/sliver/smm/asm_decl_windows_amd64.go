//go:build windows && amd64

package smm

// Assembly declarations for SMM ring-0 operations.
// Implementations are in smm_windows_amd64.s

func outByte(port uint16, val byte)
func inByte(port uint16) byte
func outDword(port uint16, val uint32)
func inDword(port uint16) uint32
func triggerSMI(apmc byte)
func readCR8() uint64
func writeCR8(val uint64)
func cli()
func sti()
func wbinvdSMM()
