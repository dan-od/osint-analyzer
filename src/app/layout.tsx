import type { Metadata, Viewport } from "next";
import { Archivo, Azeret_Mono } from "next/font/google";
import "./globals.css";

// Archivo is variable on width too: display headings use font-stretch: 75%
const archivo = Archivo({
  subsets: ["latin"],
  axes: ["wdth"],
  variable: "--font-sans",
  display: "swap",
});

// Data only: targets, IPs, DNS values, scores
const azeretMono = Azeret_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
  display: "swap",
});

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  userScalable: true,
  viewportFit: 'cover', // Important for Dynamic Island/notch
  themeColor: '#15181C',
};

export const metadata: Metadata = {
  title: "OSINT Analyzer",
  description: "Check an IP, domain, email, phone number or crypto wallet against public threat-intelligence sources and get a plain-words verdict.",
  keywords: "OSINT, scam detection, IP reputation, domain reputation, blocklists, email analysis, phone lookup, crypto wallet",
  authors: [{ name: "Daniel Okoro" }],
  openGraph: {
    title: "OSINT Analyzer",
    description: "Paste it, get a plain-words verdict backed by public threat-intelligence sources.",
    type: "website",
  },
  other: {
    'mobile-web-app-capable': 'yes',
  },
  formatDetection: {
    telephone: false, // Prevent iOS from auto-linking phone numbers
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${archivo.variable} ${azeretMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
