/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0f172a',
          800: '#1e293b',
          700: '#334155',
        },
        brand: {
          blue: '#2563eb',
          green: '#059669',
          red: '#dc2626',
          amber: '#d97706',
          purple: '#7c3aed',
        },
      },
    },
  },
  plugins: [],
};
