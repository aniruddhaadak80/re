/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['class'],
  theme: {
    extend: {
      colors: {
        bg: v('bg'), surface: v('surface'), surface2: v('surface2'), line: v('line'),
        fg: v('fg'), muted: v('muted'), accent: v('accent'), accent2: v('accent2'), ink: v('ink'),
        teal: { DEFAULT: '#14B8A6', 300: '#5EEAD4', 400: '#2DD4BF', 500: '#14B8A6', 600: '#0D9488', 700: '#0F766E' },
        gold: { DEFAULT: '#F5B301', light: '#FFD166' },
        night: '#0A0A0B',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 0 1px rgb(var(--accent) / 0.35), 0 8px 40px -8px rgb(var(--accent) / 0.35)',
      },
      keyframes: {
        dash: { to: { strokeDashoffset: '-40' } },
        shimmer: { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
      },
      animation: { dash: 'dash 1.6s linear infinite', shimmer: 'shimmer 2.2s linear infinite' },
    },
  },
  plugins: [],
};
