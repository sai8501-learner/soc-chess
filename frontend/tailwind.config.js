/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#050811',
          dark: '#0a0e17',
          surface: '#0f172a',
          card: '#131c31',
          green: '#10b981',
          cyan: '#06b6d4',
          indigo: '#6366f1',
          purple: '#8b5cf6',
          red: '#ef4444',
          rose: '#f43f5e',
          amber: '#f59e0b',
        }
      },
      opacity: {
        '2': '0.02',
        '8': '0.08',
        '15': '0.15',
        '85': '0.85',
      },
      boxShadow: {
        'cyber-cyan': '0 0 25px -4px rgba(6, 182, 212, 0.4)',
        'cyber-indigo': '0 0 25px -4px rgba(99, 102, 241, 0.4)',
        'cyber-emerald': '0 0 25px -4px rgba(16, 185, 129, 0.4)',
        'cyber-rose': '0 0 25px -4px rgba(244, 63, 94, 0.4)',
      },
      fontFamily: {
        heading: ['Orbitron', 'sans-serif'],
        body: ['Rajdhani', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
