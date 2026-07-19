"use client";
import { useState, useEffect } from "react";
import { login, register, saveToken } from "@/lib/api";
import { Shield, Zap, Lock, Eye, EyeOff, ArrowRight, Terminal, GitBranch, AlertTriangle } from "lucide-react";
import { PurpleGridLogo } from "./Logo";

const THREAT_FEED = [
  { id: "CVE-2024-3094", sev: "CRITICAL", score: 10.0, desc: "XZ Utils backdoor detected" },
  { id: "CVE-2023-44487", sev: "HIGH", score: 7.5, desc: "HTTP/2 Rapid Reset vulnerability" },
  { id: "CVE-2024-21626", sev: "HIGH", score: 8.6, desc: "runc container escape" },
  { id: "CVE-2023-46604", sev: "CRITICAL", score: 10.0, desc: "ActiveMQ RCE via OpenWire" },
  { id: "CVE-2022-42889", sev: "CRITICAL", score: 9.8, desc: "Text4Shell RCE vulnerability" },
];

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#FF4D4D",
  HIGH: "#FF8C00",
  MEDIUM: "#F5C518",
};

function ThreatFeedItem({ item, delay }: { item: typeof THREAT_FEED[0]; delay: number }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(t);
  }, [delay]);

  return (
    <div
      className="flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-500"
      style={{
        background: "rgba(13,13,20,0.8)",
        border: "1px solid rgba(30,30,46,0.8)",
        opacity: visible ? 1 : 0,
        transform: visible ? "translateX(0)" : "translateX(-20px)",
      }}
    >
      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: SEV_COLOR[item.sev], boxShadow: `0 0 6px ${SEV_COLOR[item.sev]}` }} />
      <span className="font-mono text-xs flex-shrink-0" style={{ color: SEV_COLOR[item.sev] }}>{item.id}</span>
      <span className="text-xs truncate" style={{ color: "#475569" }}>{item.desc}</span>
      <span className="font-mono text-xs font-bold flex-shrink-0" style={{ color: SEV_COLOR[item.sev] }}>{item.score}</span>
    </div>
  );
}

export default function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setTimeout(() => setMounted(true), 100);
  }, []);

  async function handleSubmit() {
    setError("");
    setLoading(true);
    try {
      if (mode === "register") await register(email, password);
      const token = await login(email, password);
      saveToken(token);
      onLogin();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex" style={{ background: "var(--bg-void)" }}>

      {/* Left panel */}
      <div
        className="hidden lg:flex flex-col w-[520px] flex-shrink-0 p-10 relative overflow-hidden"
        style={{ background: "var(--bg-surface)", borderRight: "1px solid var(--border-subtle)" }}
      >
        {/* Background grid */}
        <div style={{
          position: "absolute", inset: 0, opacity: 0.03,
          backgroundImage: "linear-gradient(var(--border-default) 1px, transparent 1px), linear-gradient(90deg, var(--border-default) 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }} />

        {/* Glow orb */}
        <div style={{
          position: "absolute", top: "20%", left: "30%",
          width: 300, height: 300,
          background: "radial-gradient(circle, rgba(124,58,237,0.08) 0%, transparent 70%)",
          pointerEvents: "none",
        }} />

        {/* Logo */}
        <div style={{ opacity: mounted ? 1 : 0, transform: mounted ? "none" : "translateY(-10px)", transition: "all 0.5s ease" }}>
          <PurpleGridLogo size={36} animated />
          <div className="mt-1 ml-1" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#475569", letterSpacing: "0.08em" }}>
            SECURITY SCANNER
          </div>
        </div>

        {/* Main copy */}
        <div className="flex-1 flex flex-col justify-center" style={{ opacity: mounted ? 1 : 0, transition: "all 0.6s ease 0.2s" }}>
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-6 w-fit"
            style={{ background: "rgba(124,58,237,0.08)", border: "1px solid rgba(124,58,237,0.2)" }}>
            <div className="w-1.5 h-1.5 rounded-full" style={{ background: "#A78BFA", animation: "pulse-purple 2s infinite" }} />
            <span style={{ color: "#A78BFA", fontSize: 11, fontWeight: 600, letterSpacing: "0.05em" }}>STATIC ANALYSIS ENGINE v4.0</span>
          </div>

          <h1 style={{ fontSize: 36, fontWeight: 800, lineHeight: 1.1, letterSpacing: "-0.03em", color: "var(--text-primary)", marginBottom: 16 }}>
            Find vulnerabilities<br />
            <span className="gradient-text">before they find you.</span>
          </h1>

          <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--text-secondary)", maxWidth: 380, marginBottom: 32 }}>
            Real static analysis powered by Bandit and Semgrep. 
            Scan any public repository and get structured findings 
            with CVSS scores in seconds.
          </p>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-4 mb-10">
            {[
              { value: "2", unit: "engines", label: "Bandit + Semgrep" },
              { value: "CVSS", unit: "v3.1", label: "Risk scoring" },
              { value: "CWE", unit: "classified", label: "All findings" },
            ].map((s) => (
              <div key={s.label} className="gradient-border p-3">
                <div style={{ fontSize: 20, fontWeight: 800, color: "var(--text-primary)" }}>
                  {s.value}<span style={{ fontSize: 11, color: "#7C3AED", marginLeft: 2 }}>{s.unit}</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Live threat feed */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Terminal size={12} style={{ color: "#7C3AED" }} />
              <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "#7C3AED", letterSpacing: "0.05em" }}>
                LIVE THREAT FEED
              </span>
              <div className="flex-1 h-px" style={{ background: "var(--border-subtle)" }} />
            </div>
            <div className="space-y-2">
              {THREAT_FEED.map((item, i) => (
                <ThreatFeedItem key={item.id} item={item} delay={400 + i * 150} />
              ))}
            </div>
          </div>
        </div>

        {/* Bottom features */}
        <div className="space-y-2" style={{ opacity: mounted ? 1 : 0, transition: "all 0.6s ease 0.4s" }}>
          {[
            { icon: Shield, text: "JWT-authenticated · bcrypt-hashed passwords" },
            { icon: GitBranch, text: "Scan any public Git repository and branch" },
            { icon: Lock, text: "Findings persisted securely in PostgreSQL" },
          ].map(({ icon: Icon, text }) => (
            <div key={text} className="flex items-center gap-3">
              <Icon size={13} style={{ color: "#7C3AED", flexShrink: 0 }} />
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{text}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Right panel — form */}
      <div className="flex-1 flex items-center justify-center p-8" style={{ background: "var(--bg-void)" }}>
        <div
          className="w-full max-w-[400px]"
          style={{ opacity: mounted ? 1 : 0, transform: mounted ? "none" : "translateY(20px)", transition: "all 0.5s ease 0.1s" }}
        >
          {/* Mobile logo */}
          <div className="flex items-center gap-3 mb-10 lg:hidden">
            <PurpleGridLogo size={28} />
            <span style={{ fontWeight: 700, fontSize: 16, color: "var(--text-primary)" }}>purplegrid</span>
          </div>

          <div className="mb-8">
            <h2 style={{ fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em", color: "var(--text-primary)", marginBottom: 6 }}>
              {mode === "login" ? "Welcome back" : "Create account"}
            </h2>
            <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
              {mode === "login" ? "Sign in to your workspace" : "Start scanning repositories"}
            </p>
          </div>

          {/* Mode toggle */}
          <div className="flex gap-1 p-1 rounded-xl mb-6" style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)" }}>
            {(["login", "register"] as const).map((m) => (
              <button key={m} onClick={() => setMode(m)}
                className="flex-1 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200"
                style={{
                  background: mode === m ? "var(--accent-primary)" : "transparent",
                  color: mode === m ? "#fff" : "var(--text-muted)",
                  letterSpacing: "-0.01em",
                }}>
                {m === "login" ? "Sign in" : "Register"}
              </button>
            ))}
          </div>

          {/* Fields */}
          <div className="space-y-4 mb-6">
            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 6, letterSpacing: "0.02em" }}>
                EMAIL ADDRESS
              </label>
              <input
                type="email" value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="input-field w-full px-4 py-3 rounded-xl text-sm"
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 6, letterSpacing: "0.02em" }}>
                PASSWORD
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"} value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                  placeholder="••••••••"
                  className="input-field w-full px-4 py-3 pr-12 rounded-xl text-sm"
                />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2"
                  style={{ color: "var(--text-muted)" }}>
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>
          </div>

          {error && (
            <div className="flex items-start gap-3 px-4 py-3 rounded-xl mb-4 text-sm"
              style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)", color: "#FCA5A5" }}>
              <AlertTriangle size={15} className="flex-shrink-0 mt-0.5" />
              {error}
            </div>
          )}

          <button onClick={handleSubmit} disabled={loading || !email || !password}
            className="btn-primary w-full py-3.5 rounded-xl text-sm flex items-center justify-center gap-2 relative z-10">
            {loading ? (
              <>
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Authenticating...
              </>
            ) : (
              <>
                {mode === "login" ? "Sign in" : "Create account"}
                <ArrowRight size={15} />
              </>
            )}
          </button>

          <p className="text-center mt-6" style={{ fontSize: 11, color: "var(--text-muted)" }}>
            JWT · bcrypt · PostgreSQL · End-to-end encrypted
          </p>
        </div>
      </div>
    </div>
  );
}