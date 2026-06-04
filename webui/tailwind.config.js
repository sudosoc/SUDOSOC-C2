/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // ── Base canvas ───────────────────────────────────────────────────────
        bg:      '#080808',   // near-pure black
        surface: '#111111',   // dark charcoal panels
        border:  '#242424',   // dark grey dividers

        // ── Blood red — the ONLY accent color ────────────────────────────────
        primary: '#b91c1c',   // blood red (crimson) — active, selected, live
        danger:  '#ef4444',   // brighter red — errors, kills, dead sessions
        warn:    '#b45309',   // dark amber-brown — warnings (not too bright)

        // ── Greyscale palette ─────────────────────────────────────────────────
        text:    '#f0f0f0',   // near-white main text
        accent:  '#d0d0d0',   // light grey — secondary labels
        muted:   '#6b6b6b',   // medium grey — disabled / metadata
        purple:  '#444444',   // dark grey — repurposed for subtle fills

        // ── Special ───────────────────────────────────────────────────────────
        info:    '#888888',
        success: '#b91c1c',   // maps to primary (red = operator success)
        error:   '#ef4444',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
      boxShadow: {
        'glow-red': '0 0 16px 0 rgba(185,28,28,0.4)',
        'glow-sm':  '0 0 8px 0 rgba(185,28,28,0.2)',
      },
    },
  },
  plugins: [],
}
