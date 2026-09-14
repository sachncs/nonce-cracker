/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
        display: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "sans-serif",
        ],
      },
      colors: {
        ink: {
          950: "#08090B",
          900: "#0B0C10",
          850: "#0F1014",
          800: "#131418",
          750: "#17181D",
          700: "#1C1D23",
          600: "#23252C",
          500: "#2C2F37",
          400: "#3A3D47",
        },
        accent: {
          50: "#FFF8EB",
          100: "#FEEBC7",
          200: "#FCD9A0",
          300: "#FABF6E",
          400: "#F7A24A",
          500: "#F1823A",
          600: "#E3651F",
          700: "#B94A12",
          800: "#923A12",
          900: "#762F12",
        },
        flame: {
          500: "#FF6B35",
          600: "#E84816",
        },
      },
      fontSize: {
        "display-xl": ["clamp(3rem, 6.5vw, 5.75rem)", { lineHeight: "0.95", letterSpacing: "-0.04em", fontWeight: "600" }],
        "display-lg": ["clamp(2.25rem, 4.5vw, 3.75rem)", { lineHeight: "1.02", letterSpacing: "-0.035em", fontWeight: "600" }],
        "display-md": ["clamp(1.75rem, 3vw, 2.5rem)", { lineHeight: "1.1", letterSpacing: "-0.03em", fontWeight: "600" }],
      },
      letterSpacing: {
        tightest: "-0.045em",
        tighter: "-0.03em",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(241,130,58,0.15), 0 8px 40px -8px rgba(241,130,58,0.25)",
        soft: "0 1px 0 rgba(255,255,255,0.04) inset, 0 24px 60px -30px rgba(0,0,0,0.6)",
        ring: "0 0 0 1px rgba(255,255,255,0.06)",
      },
      backgroundImage: {
        "grid-faint":
          "linear-gradient(to right, rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.04) 1px, transparent 1px)",
        "noise":
          "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0.05 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>\")",
        "gradient-radial":
          "radial-gradient(ellipse at center, rgba(241,130,58,0.18), rgba(241,130,58,0) 60%)",
        "gradient-conic":
          "conic-gradient(from 230deg at 50% 50%, rgba(241,130,58,0.18), rgba(232,72,22,0.12), rgba(11,12,16,0) 60%)",
      },
      animation: {
        "spin-slow": "spin 18s linear infinite",
        "pulse-soft": "pulse-soft 4s ease-in-out infinite",
        "marquee": "marquee 60s linear infinite",
        "shimmer": "shimmer 6s linear infinite",
      },
      keyframes: {
        "pulse-soft": {
          "0%, 100%": { opacity: "0.5" },
          "50%": { opacity: "1" },
        },
        marquee: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-50%)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "200% 0" },
          "100%": { backgroundPosition: "-200% 0" },
        },
      },
    },
  },
  plugins: [],
};