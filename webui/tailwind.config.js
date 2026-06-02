/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:      '#0a0a0f',
        surface: '#111122',
        border:  '#222244',
        primary: '#00ff88',
        accent:  '#00d4ff',
        warn:    '#ffaa00',
        danger:  '#ff4444',
        muted:   '#555577',
        text:    '#e0e0e0',
        purple:  '#aa88ff',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
