/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Every colour resolves through a CSS variable holding "R G B"
        // channels, so a single class works in both themes and alpha
        // modifiers (bg-surface/60) still compose.
        canvas: 'rgb(var(--c-canvas) / <alpha-value>)',
        surface: 'rgb(var(--c-surface) / <alpha-value>)',
        raised: 'rgb(var(--c-raised) / <alpha-value>)',
        sunken: 'rgb(var(--c-sunken) / <alpha-value>)',
        line: 'rgb(var(--c-line) / <alpha-value>)',
        'line-strong': 'rgb(var(--c-line-strong) / <alpha-value>)',
        ink: 'rgb(var(--c-ink) / <alpha-value>)',
        'ink-2': 'rgb(var(--c-ink-2) / <alpha-value>)',
        'ink-3': 'rgb(var(--c-ink-3) / <alpha-value>)',
        accent: 'rgb(var(--c-accent) / <alpha-value>)',
        'accent-hover': 'rgb(var(--c-accent-hover) / <alpha-value>)',
        'accent-soft': 'rgb(var(--c-accent-soft) / <alpha-value>)',
        critical: 'rgb(var(--c-critical) / <alpha-value>)',
        high: 'rgb(var(--c-high) / <alpha-value>)',
        medium: 'rgb(var(--c-medium) / <alpha-value>)',
        low: 'rgb(var(--c-low) / <alpha-value>)',
        info: 'rgb(var(--c-info) / <alpha-value>)',
        success: 'rgb(var(--c-success) / <alpha-value>)',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['10.5px', { lineHeight: '14px', letterSpacing: '0.02em' }],
        xs: ['11.5px', { lineHeight: '16px' }],
        sm: ['12.5px', { lineHeight: '18px' }],
        base: ['13.5px', { lineHeight: '20px' }],
        md: ['14.5px', { lineHeight: '22px' }],
        lg: ['16px', { lineHeight: '24px' }],
        xl: ['19px', { lineHeight: '27px' }],
        '2xl': ['23px', { lineHeight: '30px' }],
        '3xl': ['29px', { lineHeight: '36px' }],
      },
      borderRadius: {
        DEFAULT: '4px',
        md: '5px',
        lg: '7px',
      },
      boxShadow: {
        panel: '0 1px 2px rgb(0 0 0 / 0.05)',
        pop: '0 8px 24px -6px rgb(0 0 0 / 0.28), 0 2px 6px -2px rgb(0 0 0 / 0.18)',
      },
      transitionDuration: { 120: '120ms' },
      keyframes: {
        'fade-in': { from: { opacity: 0 }, to: { opacity: 1 } },
        'slide-up': {
          from: { opacity: 0, transform: 'translateY(6px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 140ms ease-out',
        'slide-up': 'slide-up 160ms ease-out',
      },
    },
  },
  plugins: [],
};
