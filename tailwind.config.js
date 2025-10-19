/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"Roboto Mono"', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out',
        'blink': 'blink 1s step-end infinite',
        'glow': 'glow 1.5s ease-in-out infinite alternate',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        blink: {
          'from, to': { borderColor: 'transparent' },
          '50%': { borderColor: 'rgb(52, 211, 153)' }, // Corresponds to green-400
        },
        glow: {
          'from': { textShadow: '0 0 5px #34d399, 0 0 10px #34d399, 0 0 15px #34d399' },
          'to': { textShadow: '0 0 10px #34d399, 0 0 20px #34d399, 0 0 30px #34d399' },
        },
      },
    },
  },
  plugins: [],
}