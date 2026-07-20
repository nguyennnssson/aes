import type { Config } from "tailwindcss";

// AES web — LIGHT theme. White/very-light page, near-black ink, vivid semantic
// accents so devices / data / graphs / status stand out.
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        page: "#F6F8FB",
        surface: { DEFAULT: "#FFFFFF", 2: "#EEF2F7" },
        line: { DEFAULT: "#E3E8EF", strong: "#CBD5E1" },
        ink: { DEFAULT: "#0D1626", 2: "#475569", muted: "#94A3B8" },
        // semantic status / data accents
        clean: { DEFAULT: "#16A34A", soft: "#DCFCE7" },
        warming: { DEFAULT: "#CA8A04", soft: "#FEF9C3" },
        elevated: { DEFAULT: "#EA580C", soft: "#FFEDD5" },
        attack: { DEFAULT: "#DC2626", soft: "#FEE2E2" },
        info: { DEFAULT: "#2563EB", soft: "#DBEAFE" },
        data: { DEFAULT: "#0891B2", soft: "#CFFAFE" },
        ai: { DEFAULT: "#7C3AED", soft: "#EDE9FE" },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "JetBrains Mono", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(13,22,38,0.04), 0 1px 3px rgba(13,22,38,0.06)",
        pop: "0 6px 24px rgba(13,22,38,0.10)",
        glow: "0 0 0 1px rgba(220,38,38,0.30), 0 0 26px rgba(220,38,38,0.18)",
      },
    },
  },
  plugins: [],
};

export default config;
