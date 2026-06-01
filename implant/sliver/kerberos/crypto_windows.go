package kerberos

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Kerberos cryptographic primitives.

	Kerberos supports multiple encryption types (etypes):
	  17  AES128-CTS-HMAC-SHA1-96   (modern default)
	  18  AES256-CTS-HMAC-SHA1-96   (preferred)
	  23  RC4-HMAC                  (legacy, still supported everywhere)
	  -128 RC4-HMAC-OLD             (very old, Windows 2000)

	For ticket forging we primarily use:
	  etype 23 (RC4-HMAC) — only requires the NT hash (MD4 of password)
	  etype 18 (AES256)   — requires the AES256 key from DCSync

	RC4-HMAC key derivation:
	  The session key for RC4-HMAC is the NT hash itself.
	  Encryption: HMAC-MD5(key, usage_constant || HMAC-MD5(key, plaintext))
	  where usage_constant varies by message type (8 for TGT enc-part, etc.)

	AES key derivation (RFC 3962):
	  AES key is derived from password via PBKDF2-SHA1 + AES-CTS.
	  For ticket forging, we take the raw AES256 key from DCSync output.

	Message encryption (RFC 4120):
	  KRB5 encrypted data structure:
	    etype       int
	    kvno        int (optional)
	    cipher      bytes = encrypt(key, usage, plaintext)
*/

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

// Kerberos encryption type constants.
const (
	EtypeRC4HMAC    = 23
	EtypeAES128     = 17
	EtypeAES256     = 18
)

// Kerberos key usage numbers (RFC 4120 §7.5.1).
const (
	KeyUsageAsRepEncPart        = 3
	KeyUsageTgsRepEncPartSubKey = 8
	KeyUsageTgsRepEncPartSessKey= 9
	KeyUsageTicketEncPart       = 2
	KeyUsagePacServerSignature  = 6
	KeyUsagePacKDCSignature     = 19
)

// RC4HMACEncrypt encrypts plaintext with the given NT hash using RC4-HMAC.
// The NT hash is the raw 16-byte MD4(UTF-16LE(password)) value.
func RC4HMACEncrypt(ntHash []byte, keyUsage uint32, plaintext []byte) ([]byte, error) {
	// RFC 4757 RC4-HMAC key schedule:
	// K1 = HMAC-MD5(NT_hash, Ksign || usage_le)  where Ksign = "signaturekey\0"
	// K3 = HMAC-MD5(K1, checksum)
	// checksum = HMAC-MD5(K1, plaintext)
	// ciphertext = RC4(K3, plaintext)
	// output = checksum + ciphertext

	// Build the usage constant (little-endian uint32).
	usageBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBuf, keyUsage)

	// K1 = HMAC-MD5(ntHash, L40 || usage)
	// L40 = "fortybits" (historical artefact, ignored for modern RC4-HMAC)
	k1 := hmacMD5(ntHash, append([]byte("signaturekey\x00"), usageBuf...))

	// checksum = HMAC-MD5(K1, plaintext)
	checksum := hmacMD5(k1, plaintext)

	// K3 = HMAC-MD5(K1, checksum)
	k3 := hmacMD5(k1, checksum)

	// cipher = RC4(K3, plaintext)
	cipher, err := rc4Stream(k3, plaintext)
	if err != nil {
		return nil, err
	}

	// output = checksum || cipher
	return append(checksum, cipher...), nil
}

// RC4HMACDecrypt decrypts RC4-HMAC ciphertext using the NT hash.
func RC4HMACDecrypt(ntHash []byte, keyUsage uint32, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, errorf("RC4-HMAC ciphertext too short: %d", len(ciphertext))
	}
	usageBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBuf, keyUsage)

	k1 := hmacMD5(ntHash, append([]byte("signaturekey\x00"), usageBuf...))

	checksum := ciphertext[:16]
	encData := ciphertext[16:]

	k3 := hmacMD5(k1, checksum)
	plaintext, err := rc4Stream(k3, encData)
	if err != nil {
		return nil, err
	}

	// Verify checksum.
	expected := hmacMD5(k1, plaintext)
	if !hmacEqual(expected, checksum) {
		return nil, errorf("RC4-HMAC checksum mismatch")
	}
	return plaintext, nil
}

// AES256CTSEncrypt encrypts plaintext with AES256-CTS-HMAC-SHA1-96.
// aesKey must be the 32-byte raw AES256 key (from DCSync output).
func AES256CTSEncrypt(aesKey []byte, keyUsage uint32, plaintext []byte) ([]byte, error) {
	if len(aesKey) != 32 {
		return nil, errorf("AES256 key must be 32 bytes, got %d", len(aesKey))
	}

	// RFC 3962 key derivation for encryption:
	// Ke = DK(aesKey, usage || 0xAA)
	// Ki = DK(aesKey, usage || 0x55)
	ke, err := driveKey(aesKey, keyUsage, 0xAA, 32)
	if err != nil {
		return nil, err
	}
	ki, err := driveKey(aesKey, keyUsage, 0x55, 32)
	if err != nil {
		return nil, err
	}

	// Pad plaintext to 16-byte boundary.
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// AES-CTS encrypt.
	cipher, err := aesCTSEncrypt(ke, padded)
	if err != nil {
		return nil, err
	}

	// HMAC-SHA1-96 integrity check.
	mac := hmacSHA1_96(ki, plaintext)

	return append(mac, cipher...), nil
}

// AES256CTSDecrypt decrypts AES256-CTS-HMAC-SHA1-96 ciphertext.
func AES256CTSDecrypt(aesKey []byte, keyUsage uint32, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, errorf("AES256-CTS ciphertext too short")
	}
	ke, err := driveKey(aesKey, keyUsage, 0xAA, 32)
	if err != nil {
		return nil, err
	}
	ki, err := driveKey(aesKey, keyUsage, 0x55, 32)
	if err != nil {
		return nil, err
	}

	mac := ciphertext[:12]
	encData := ciphertext[12:]

	plaintext, err := aesCTSDecrypt(ke, encData)
	if err != nil {
		return nil, err
	}
	// Strip padding.
	plaintext = stripPKCS7(plaintext, aes.BlockSize)

	expected := hmacSHA1_96(ki, plaintext)
	if !hmacEqual(expected, mac) {
		return nil, errorf("AES256 HMAC-SHA1 mismatch")
	}
	return plaintext, nil
}

// ─── Low-level crypto helpers ─────────────────────────────────────────────

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hmacSHA1_96(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)[:12] // truncated to 96 bits
}

func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func rc4Stream(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// driveKey implements RFC 3962 DK(key, constant, keyLen) for AES.
// DK(key, constant) = random-to-key(PRF+(key, constant))
func driveKey(key []byte, usage uint32, suffix byte, keyLen int) ([]byte, error) {
	// constant = usage_be(4) || suffix(1)
	constant := make([]byte, 5)
	binary.BigEndian.PutUint32(constant, usage)
	constant[4] = suffix
	return prfPlus(key, constant, keyLen)
}

// prfPlus computes PBKDF2-like PRF expansion using AES in CBC mode.
func prfPlus(key, constant []byte, length int) ([]byte, error) {
	var result []byte
	i := byte(1)
	for len(result) < length {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		// Nfold the constant to blocksize, then CBC-encrypt.
		folded := nFold(append(constant, i), 16)
		out := make([]byte, 16)
		block.Encrypt(out, folded)
		result = append(result, out...)
		i++
	}
	return result[:length], nil
}

// nFold implements the Kerberos n-fold operation (RFC 3961).
// Produces a dst-length byte slice by cyclically xoring src.
func nFold(src []byte, dst int) []byte {
	lcm := lcmLen(len(src), dst)
	expanded := make([]byte, lcm)
	for i := 0; i < lcm/len(src); i++ {
		shifted := rotateRight(src, i*13)
		for j, b := range shifted {
			expanded[i*len(src)+j] ^= b
		}
	}
	result := make([]byte, dst)
	for i := 0; i < lcm/dst; i++ {
		for j := 0; j < dst; j++ {
			result[j] ^= expanded[i*dst+j]
		}
	}
	return result
}

func rotateRight(b []byte, n int) []byte {
	l := len(b)
	n = n % (l * 8)
	out := make([]byte, l)
	for i := 0; i < l*8; i++ {
		srcBit := i
		dstBit := (i + n) % (l * 8)
		if b[srcBit/8]>>(7-uint(srcBit%8))&1 != 0 {
			out[dstBit/8] |= 1 << (7 - uint(dstBit%8))
		}
	}
	return out
}

func lcmLen(a, b int) int {
	return a * b / gcd(a, b)
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// aesCTSEncrypt implements AES-CTS (Ciphertext Stealing) mode.
func aesCTSEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext)%aes.BlockSize != 0 || len(plaintext) < 2*aes.BlockSize {
		// For short plaintexts, fall back to CBC.
		return aesCBCEncrypt(key, make([]byte, aes.BlockSize), plaintext)
	}
	// Standard CBC for all but last two blocks, then swap.
	iv := make([]byte, aes.BlockSize)
	n := len(plaintext)
	cbc, _ := aesCBCEncrypt(key, iv, plaintext[:n-aes.BlockSize])
	lastBlock := plaintext[n-aes.BlockSize:]
	penultimate := cbc[len(cbc)-aes.BlockSize:]

	for i := range lastBlock {
		lastBlock[i] ^= penultimate[i]
	}
	var encLast [aes.BlockSize]byte
	block.Encrypt(encLast[:], lastBlock)

	result := make([]byte, n)
	copy(result, cbc[:len(cbc)-aes.BlockSize])
	copy(result[n-aes.BlockSize:], encLast[:])
	copy(result[n-2*aes.BlockSize:n-aes.BlockSize], penultimate)
	return result, nil
}

func aesCTSDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2*aes.BlockSize {
		return aesCBCDecrypt(key, make([]byte, aes.BlockSize), ciphertext)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)
	penultimate := ciphertext[n-2*aes.BlockSize : n-aes.BlockSize]
	last := ciphertext[n-aes.BlockSize:]

	var decPenultimate [aes.BlockSize]byte
	block.Decrypt(decPenultimate[:], penultimate)

	restored := make([]byte, 2*aes.BlockSize)
	copy(restored[:aes.BlockSize], last)
	for i := aes.BlockSize; i < 2*aes.BlockSize; i++ {
		restored[i] = decPenultimate[i-aes.BlockSize] ^ 0
	}
	copy(restored[aes.BlockSize:], decPenultimate[:])

	return aesCBCDecrypt(key, ciphertext[n-3*aes.BlockSize:n-2*aes.BlockSize],
		append(ciphertext[:n-2*aes.BlockSize], restored...))
}

func aesCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	prev := iv
	for i := 0; i < len(data); i += aes.BlockSize {
		chunk := data[i : i+aes.BlockSize]
		xored := make([]byte, aes.BlockSize)
		for j := range chunk {
			xored[j] = chunk[j] ^ prev[j]
		}
		block.Encrypt(out[i:], xored)
		prev = out[i : i+aes.BlockSize]
	}
	return out, nil
}

func aesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	prev := iv
	for i := 0; i < len(data); i += aes.BlockSize {
		chunk := data[i : i+aes.BlockSize]
		dec := make([]byte, aes.BlockSize)
		block.Decrypt(dec, chunk)
		for j := range dec {
			out[i+j] = dec[j] ^ prev[j]
		}
		prev = chunk
	}
	return out, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	return padded
}

func stripPKCS7(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return data
	}
	return data[:len(data)-pad]
}

func errorf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}
