/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // ── Deep navy-black backgrounds ──────────────────────────────────────
        bg:      '#07070f',   // deep navy-black — base canvas
        surface: '#0d0d1e',   // panel / card background
        border:  '#1c1c38',   // subtle blue-tinted dividers

        // ── Semantic colors ───────────────────────────────────────────────────
        primary: '#00e676',   // green — sessions / alive / success
        accent:  '#29b6f6',   // sky-blue — info / beacons / links
        warn:    '#ffa726',   // amber — warnings / listeners / pending
        danger:  '#ef5350',   // red — kills / errors / dead
        purple:  '#b39ddb',   // soft purple — loot / misc
        muted:   '#7070a0',   // readable muted text (was #555577 — too dark)
        text:    '#e2e2f0',   // slightly blue-tinted white

        // ── Aliases used in some components ──────────────────────────────────
        info:    '#29b6f6',
        success: '#00e676',
        error:   '#ef5350',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
      boxShadow: {
        glow:       '0 0 12px 0 rgba(0,230,118,0.25)',
        'glow-blue':'0 0 12px 0 rgba(41,182,246,0.25)',
        'glow-red': '0 0 12px 0 rgba(239,83,80,0.25)',
      },
    },
  },
  plugins: [],
}
