/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // ── Base canvas ───────────────────────────────────────────────────
        bg:      '#080808',
        surface: '#111111',
        border:  '#242424',

        // ── Blood red — the ONLY accent ───────────────────────────────────
        primary: '#b91c1c',
        danger:  '#ef4444',
        warn:    '#b45309',

        // ── Greyscale ─────────────────────────────────────────────────────
        text:    '#f0f0f0',
        accent:  '#d0d0d0',
        muted:   '#6b6b6b',
        dim:     '#2a2a2a',
        purple:  '#444444',

        // ── Aliases ───────────────────────────────────────────────────────
        info:    '#888888',
        success: '#b91c1c',
        error:   '#ef4444',
      },

      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'ui-monospace', 'monospace'],
      },

      fontSize: {
        '2xs': ['9px',  { lineHeight: '1.4' }],
        'xs':  ['10px', { lineHeight: '1.5' }],
        'sm':  ['11px', { lineHeight: '1.55' }],
        'base':['12.5px',{ lineHeight: '1.55' }],
      },

      spacing: {
        '0.5': '2px',
        '1':   '4px',
        '1.5': '6px',
        '2':   '8px',
        '2.5': '10px',
        '3':   '12px',
        '3.5': '14px',
        '4':   '16px',
      },

      borderRadius: {
        'sm':  '3px',
        DEFAULT:'5px',
        'md':  '6px',
        'lg':  '8px',
        'xl':  '10px',
        '2xl': '14px',
      },

      boxShadow: {
        'glow-red':  '0 0 20px 0 rgba(185,28,28,0.3)',
        'glow-sm':   '0 0 8px  0 rgba(185,28,28,0.15)',
        'card':      '0 1px 3px 0 rgba(0,0,0,0.4)',
        'panel':     '0 4px 20px 0 rgba(0,0,0,0.5)',
      },

      backgroundOpacity: {
        '3':  '0.03',
        '4':  '0.04',
        '8':  '0.08',
        '12': '0.12',
        '15': '0.15',
        '18': '0.18',
      },

      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'fadein':     'fadeIn .18s ease',
        'slidein':    'slideLeft .18s ease',
      },

      transitionDuration: {
        '100': '100ms',
        '120': '120ms',
        '150': '150ms',
      },
    },
  },
  plugins: [],
}
