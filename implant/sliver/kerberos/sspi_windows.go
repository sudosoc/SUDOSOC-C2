//go:build windows

package kerberos

// SSPI types and helpers for the kerberos package.
// AcquireCredentialsHandle / InitializeSecurityContext are in secur32.dll
// but are not fully exposed by golang.org/x/sys/windows.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSecur32Kerb         = windows.NewLazySystemDLL("secur32.dll")
	procAcquireCreds       = modSecur32Kerb.NewProc("AcquireCredentialsHandleW")
	procInitSecCtxKerb     = modSecur32Kerb.NewProc("InitializeSecurityContextW")
	procFreeCredsKerb      = modSecur32Kerb.NewProc("FreeCredentialsHandle")
	procDeleteSecCtxKerb   = modSecur32Kerb.NewProc("DeleteSecurityContext")
)

// sspiCredHandle is the SSPI credential handle (two pointer-sized words).
type sspiCredHandle struct{ Lower, Upper uintptr }

// sspiCtxtHandle is the SSPI security context handle.
type sspiCtxtHandle struct{ Lower, Upper uintptr }

// sspiSecInt is SECURITY_INTEGER.
type sspiSecInt struct{ Low uint32; High int32 }

// sspiSecBuffer is one buffer entry.
type sspiSecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

// sspiSecBufferDesc is the descriptor for a set of SecBuffers.
type sspiSecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  uintptr // pointer to first sspiSecBuffer
}

const (
	sspiSECPKG_CRED_OUTBOUND    = 2
	sspiSECBUFFER_VERSION       = 0
	sspiSECBUFFER_TOKEN         = 2
	sspiSECBUFFER_EXTRA         = 5
	sspiISC_REQ_ALLOCATE_MEMORY = 0x00000100
	sspiISC_REQ_CONNECTION      = 0x00000800
	sspiISC_REQ_DELEGATE        = 0x00000001
	sspiSEC_I_CONTINUE_NEEDED   = uintptr(0x00090312)
	_ = unsafe.Sizeof(sspiSecBuffer{}) // ensure unsafe imported
)
