import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Purple-Grid — Vulnerability Scanner",
  description: "AI-powered static analysis and vulnerability detection for source code repositories.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}