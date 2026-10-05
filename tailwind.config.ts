import type { Config } from "tailwindcss";

// Tokens mirror the CSS variables in src/app/globals.css (design/mockups/Styles.dc.html)
export default {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ground: "#15181C",
        panel: "#1A1E23",
        raised: "#22272D",
        foot: "#121518",
        line: { DEFAULT: "#2C3238", strong: "#3A4149", hover: "#4A525B" },
        ink: { DEFAULT: "#E6E9EC", strong: "#FFFFFF", body: "#C9D0D6" },
        muted: "#9AA3AD",
        faint: "#6E7781",
        skip: "#8B949E",
        accent: "#F28C28",
        link: "#8FB8F5",
        fail: { DEFAULT: "#F0705C", ink: "#F58B7A", bg: "#1E171A", badge: "#3A1A16" },
        warn: { DEFAULT: "#F2CE4E", bg: "#1F1B14" },
        pass: { DEFAULT: "#5FCB8F", ink: "#6FCB95" },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["var(--font-mono)", "Menlo", "monospace"],
      },
      borderRadius: {
        DEFAULT: "3px",
      },
    },
  },
  plugins: [],
} satisfies Config;
