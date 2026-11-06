import type { Config } from "tailwindcss";

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#08080a",
          900: "#0c0c0f",
          850: "#101013",
          800: "#141417",
          750: "#18181c",
          700: "#1d1d22",
          650: "#232329",
          600: "#2a2a31",
          500: "#3a3a43",
          400: "#5c5c68",
          300: "#8a8a96",
          200: "#b4b2ac",
          100: "#ddd8cc",
          50: "#f6f2e9",
        },
        amber: {
          50: "#fff8e6",
          100: "#ffedbf",
          200: "#ffdd85",
          300: "#fdc94f",
          400: "#f5b025",
          500: "#e89a12",
          600: "#c47a0a",
          700: "#9a5b0b",
          800: "#7d4910",
          900: "#683c0f",
        },
        ember: {
          400: "#ff7a3d",
          500: "#f65c1b",
          600: "#dd470e",
          700: "#b7390c",
        },
        cream: "#f4efe3",
      },
      fontFamily: {
        sans: ["'Instrument Sans Variable'", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono Variable'", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 rgba(255,255,255,0.03) inset, 0 18px 40px -32px rgba(0,0,0,0.9)",
        lift: "0 24px 60px -30px rgba(0,0,0,0.85)",
      },
      keyframes: {
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        pulseSoft: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.45" },
        },
      },
      animation: {
        shimmer: "shimmer 1.8s infinite",
        pulseSoft: "pulseSoft 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;
