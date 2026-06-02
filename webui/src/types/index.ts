// ─── API response types (mirror server/web/api.go) ───────────────────────────

export interface Stats {
  sessions:  number
  beacons:   number
  listeners: number
  operators: number
  uptime:    string
}

export interface Session {
  id:             string
  name:           string
  hostname:       string
  username:       string
  os:             string
  arch:           string
  transport:      string
  remote_address: string
  pid:            number
  last_checkin:   number   // unix timestamp
  is_dead:        boolean
  active_c2:      string
}

export interface Beacon {
  id:             string
  name:           string
  hostname:       string
  username:       string
  os:             string
  arch:           string
  transport:      string
  remote_address: string
  last_checkin:   number   // unix timestamp
  next_checkin:   number   // unix timestamp
  interval:       number   // milliseconds
  active_c2:      string
}

export interface Listener {
  id:       number
  name:     string
  protocol: string
  port:     number
  domains:  string[] | null
}

export interface LootItem {
  id:        string
  name:      string
  file_type: number
  size:      number
}

export interface Operator {
  name:   string
  online: boolean
}

// ─── WebSocket event envelope ────────────────────────────────────────────────

export interface WSEvent {
  type:    string
  payload: Record<string, unknown>
  time:    number
}

// ─── Terminal WebSocket message ───────────────────────────────────────────────

export interface TermMsg {
  type: 'input' | 'output' | 'prompt' | 'error'
  data: string
}
