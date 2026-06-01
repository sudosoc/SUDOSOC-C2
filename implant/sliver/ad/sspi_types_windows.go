//go:build windows

package ad

// SSPI types not exported by golang.org/x/sys/windows.
// Defined here for Kerberoasting (AcquireCredentialsHandle / InitializeSecurityContext).

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSecur32             = windows.NewLazySystemDLL("secur32.dll")
	procAcquireCredentials = modSecur32.NewProc("AcquireCredentialsHandleW")
	procInitSecCtx         = modSecur32.NewProc("InitializeSecurityContextW")
	procFreeCredentials    = modSecur32.NewProc("FreeCredentialsHandle")
	procFreeCtxBuffer      = modSecur32.NewProc("FreeContextBuffer")
	procDeleteSecCtx       = modSecur32.NewProc("DeleteSecurityContext")
)

// CredHandle is the SSPI credential handle (two pointer-sized fields).
type CredHandle struct {
	Lower uintptr
	Upper uintptr
}

// CtxtHandle is the SSPI security context handle.
type CtxtHandle struct {
	Lower uintptr
	Upper uintptr
}

// SecurityInteger is the SSPI SECURITY_INTEGER (maps to LARGE_INTEGER).
type SecurityInteger struct {
	LowPart  uint32
	HighPart int32
}

// SecBuffer is one buffer in a SecBufferDesc.
type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

// SecBufferDesc is a set of SecBuffers passed to SSPI functions.
type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  uintptr
}

const (
	SECPKG_CRED_OUTBOUND = 2
	SECBUFFER_VERSION    = 0
	SECBUFFER_TOKEN      = 2
	ISC_REQ_ALLOCATE_MEMORY = 0x00000100
	ISC_REQ_CONNECTION      = 0x00000800
)

// AcquireCredentialsHandle wraps the SSPI call.
func AcquireCredentialsHandle(
	principal *uint16,
	pkg *uint16,
	credUse uint32,
	logonID uintptr,
	authData uintptr,
	getKeyFn uintptr,
	getKeyArg uintptr,
	credential *CredHandle,
	expiry *SecurityInteger,
) error {
	r, _, err := procAcquireCredentials.Call(
		uintptr(unsafe.Pointer(principal)),
		uintptr(unsafe.Pointer(pkg)),
		uintptr(credUse),
		logonID,
		authData,
		getKeyFn,
		getKeyArg,
		uintptr(unsafe.Pointer(credential)),
		uintptr(unsafe.Pointer(expiry)),
	)
	if r != 0 {
		return err
	}
	return nil
}

// FreeCredentialsHandle releases a credential handle.
func FreeCredentialsHandle(credential *CredHandle) {
	procFreeCredentials.Call(uintptr(unsafe.Pointer(credential)))
}
