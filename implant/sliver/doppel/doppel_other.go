//go:build !windows

package doppel

// Non-Windows stubs.

import "golang.org/x/sys/windows"

type Transaction struct{ Handle windows.Handle }

func CreateTxFTransaction() (*Transaction, error)                          { return nil, nil }
func (tx *Transaction) Rollback() error                                    { return nil }
func (tx *Transaction) Commit() error                                      { return nil }
func (tx *Transaction) Close()                                             {}
func (tx *Transaction) OpenTransacted(_ string) (windows.Handle, error)   { return 0, nil }
func WriteTransacted(_ windows.Handle, _ []byte) error                    { return nil }

type DoppelResult struct {
	ProcessHandle windows.Handle
	ThreadHandle  windows.Handle
	PID           uint32
	TID           uint32
	ImageBase     uint64
	EntryPoint    uint64
}

type HollowResult struct {
	ProcessHandle windows.Handle
	ThreadHandle  windows.Handle
	PID           uint32
	TID           uint32
	ImageBase     uint64
	EntryPoint    uint64
	OrigImageBase uint64
}

func Doppelgang(_ string, _ []byte, _ string) (*DoppelResult, error) { return nil, nil }
func TransactedHollow(_ string, _ []byte, _ string) (*HollowResult, error) { return nil, nil }
