//go:build !windows

package rowhammer

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// Linux / macOS implementation using /proc/self/pagemap.

func openPagemapPlatform(m *MemoryMapper) error {
	if _, err := os.Stat("/proc/self/pagemap"); err != nil {
		// macOS or no pagemap access.
		m.pagefile = ^uintptr(0)
		return nil
	}
	f, err := os.OpenFile("/proc/self/pagemap", os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open pagemap (need CAP_SYS_PTRACE or root): %w", err)
	}
	m.pagefile = uintptr(f.Fd())
	return nil
}

func closePagemapPlatform(m *MemoryMapper) {
	if m.pagefile != ^uintptr(0) && m.pagefile != 0 {
		syscall.Close(int(m.pagefile))
	}
}

func virtToPhysPlatform(m *MemoryMapper, va uintptr) (uint64, error) {
	if m.pagefile == ^uintptr(0) {
		return 0, fmt.Errorf("pagemap not available on this platform")
	}
	pageNum := uint64(va / m.pageSize)
	offset := int64(pageNum * 8)
	var entry uint64
	n, err := syscall.Pread(int(m.pagefile), (*[8]byte)(unsafe.Pointer(&entry))[:], offset)
	if n != 8 || err != nil {
		return 0, fmt.Errorf("pagemap read: %w", err)
	}
	// Bit 63: page present.
	if entry>>63 == 0 {
		return 0, nil
	}
	pfn := entry & 0x007FFFFFFFFFFFFF
	pa := pfn*uint64(m.pageSize) + uint64(va&^m.pageMask)
	return pa, nil
}

func allocLargeBufferPlatform(size int) ([]byte, error) {
	buf, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}
	return buf, nil
}

func freeLargeBufferPlatform(buf []byte) {
	syscall.Munmap(buf)
}

func lockMemoryPlatform(p unsafe.Pointer, n uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(p), n, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func unlockMemoryPlatform(p unsafe.Pointer, n uintptr) {
	syscall.Syscall(syscall.SYS_MUNLOCK, uintptr(p), n, 0)
}

func getPhysicalMemorySizePlatform() uint64 {
	// Read /proc/meminfo MemTotal.
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 8 * 1024 * 1024 * 1024 // default 8GB
	}
	const prefix = "MemTotal:"
	s := string(data)
	idx := 0
	for i := 0; i < len(s)-len(prefix); i++ {
		if s[i:i+len(prefix)] == prefix {
			idx = i + len(prefix)
			break
		}
	}
	// Skip spaces.
	for idx < len(s) && (s[idx] == ' ' || s[idx] == '\t') {
		idx++
	}
	end := idx
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == idx {
		return 8 * 1024 * 1024 * 1024
	}
	kb, _ := strconv.ParseUint(s[idx:end], 10, 64)
	return kb * 1024
}
