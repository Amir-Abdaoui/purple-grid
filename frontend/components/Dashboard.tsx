"use client";
import { useState, useEffect, useCallback } from "react";
import { runScan, getScanHistory, ScanResult, ScanHistoryItem } from "@/lib/api";

// ─── Types ────────────────────────────────────────────────────────────────────
interface Vuln {
  finding_id?: string;
  engine?: string;
  severity: string;
  cvss_score: number;
  cwe?: string;
  cve_id?: string;
  file_path: string;
  line_number: number;
  title?: string;
  description?: string;
  remediation?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────
const SEVS = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] as const;

const SEV: Record<string, { color: string; bg: string; border: string; glow: string; bar: string }> = {
  CRITICAL: { color:"#EF4444", bg:"rgba(239,68,68,0.08)",   border:"rgba(239,68,68,0.2)",   glow:"rgba(239,68,68,0.3)",   bar:"#EF4444" },
  HIGH:     { color:"#F59E0B", bg:"rgba(245,158,11,0.08)",  border:"rgba(245,158,11,0.2)",  glow:"rgba(245,158,11,0.3)",  bar:"#F59E0B" },
  MEDIUM:   { color:"#EAB308", bg:"rgba(234,179,8,0.08)",   border:"rgba(234,179,8,0.2)",   glow:"rgba(234,179,8,0.3)",   bar:"#EAB308" },
  LOW:      { color:"#3B82F6", bg:"rgba(59,130,246,0.08)",  border:"rgba(59,130,246,0.2)",  glow:"rgba(59,130,246,0.3)",  bar:"#3B82F6" },
  INFO:     { color:"#64748B", bg:"rgba(100,116,139,0.08)", border:"rgba(100,116,139,0.2)", glow:"rgba(100,116,139,0.2)", bar:"#64748B" },
};

const ENGINE: Record<string, { color: string }> = {
  bandit:  { color:"#8B5CF6" },
  semgrep: { color:"#06B6D4" },
  trivy:   { color:"#10B981" },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function riskColor(score: number) {
  if (score >= 9) return "#EF4444";
  if (score >= 7) return "#F59E0B";
  if (score >= 4) return "#EAB308";
  if (score > 0)  return "#3B82F6";
  return "#64748B";
}

// ─── Sub-components ───────────────────────────────────────────────────────────
function SevBadge({ s }: { s: string }) {
  const c = SEV[s] || SEV.INFO;
  return (
    <span style={{
      fontSize:9, fontFamily:"'Courier New',monospace", fontWeight:800,
      letterSpacing:"0.08em", padding:"2px 6px", borderRadius:3,
      color:c.color, background:c.bg, border:`1px solid ${c.border}`,
      whiteSpace:"nowrap" as const,
    }}>{s}</span>
  );
}

function EngBadge({ e }: { e?: string }) {
  if (!e) return null;
  const cfg = ENGINE[e.toLowerCase()] || { color:"#64748B" };
  return (
    <span style={{
      fontSize:9, fontFamily:"'Courier New',monospace", fontWeight:700,
      letterSpacing:"0.06em", padding:"2px 6px", borderRadius:3,
      color:cfg.color, background:`${cfg.color}18`, border:`1px solid ${cfg.color}35`,
      whiteSpace:"nowrap" as const,
    }}>{e.toUpperCase()}</span>
  );
}

function CWEBadge({ cwe }: { cwe?: string }) {
  if (!cwe) return null;
  return (
    <span style={{
      fontSize:9, fontFamily:"'Courier New',monospace", fontWeight:600,
      letterSpacing:"0.04em", padding:"2px 6px", borderRadius:3,
      color:"#94A3B8", background:"rgba(148,163,184,0.06)", border:"1px solid rgba(148,163,184,0.12)",
      whiteSpace:"nowrap" as const,
    }}>{cwe}</span>
  );
}

function CVSSBadge({ score }: { score: number }) {
  const color = riskColor(score);
  const pct = (score / 10) * 100;
  const r = 18, circ = 2 * Math.PI * r;
  return (
    <div style={{ position:"relative", width:46, height:46, flexShrink:0 }}>
      <svg width={46} height={46} style={{ transform:"rotate(-90deg)", position:"absolute", inset:0 }}>
        <circle cx={23} cy={23} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={3.5} />
        <circle cx={23} cy={23} r={r} fill="none" stroke={color} strokeWidth={3.5}
          strokeLinecap="round" strokeDasharray={`${(pct/100)*circ} ${circ}`}
          style={{ filter:`drop-shadow(0 0 4px ${color})`, transition:"stroke-dasharray 0.6s ease" }} />
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center", justifyContent:"center",
        fontFamily:"'Courier New',monospace", fontWeight:900, fontSize:11, color,
        textShadow:`0 0 8px ${color}` }}>
        {score.toFixed(1)}
      </div>
    </div>
  );
}

function ScanProgress({ repo }: { repo: string }) {
  const [step, setStep] = useState(0);
  const steps = ["Resolving repository…","Cloning source code…","Running Bandit SAST…","Running Semgrep rules…","Normalising findings…"];
  useEffect(() => {
    const t = setInterval(() => setStep(s => Math.min(s + 1, steps.length - 1)), 7000);
    return () => clearInterval(t);
  }, []);
  return (
    <div style={{ background:"#0B0B14", border:"1px solid rgba(139,92,246,0.15)", borderRadius:14, padding:"40px 32px", textAlign:"center", position:"relative", overflow:"hidden" }}>
      {/* Scan line */}
      <div style={{ position:"absolute", left:0, right:0, height:1, background:"linear-gradient(90deg,transparent,#8B5CF6,transparent)", top:0, animation:"scanline 2.5s linear infinite" }} />
      {/* Glow */}
      <div style={{ position:"absolute", top:"-50%", left:"50%", transform:"translateX(-50%)", width:300, height:300, background:"radial-gradient(circle,rgba(139,92,246,0.06) 0%,transparent 70%)", pointerEvents:"none" }} />

      <div style={{ position:"relative", width:72, height:72, margin:"0 auto 24px", display:"flex", alignItems:"center", justifyContent:"center" }}>
        <div style={{ position:"absolute", inset:0, borderRadius:"50%", border:"1.5px solid rgba(139,92,246,0.2)" }} />
        <div style={{ position:"absolute", inset:0, borderRadius:"50%", border:"2px solid transparent", borderTopColor:"#8B5CF6", animation:"spincw 1s linear infinite" }} />
        <div style={{ position:"absolute", inset:8, borderRadius:"50%", border:"1.5px solid transparent", borderTopColor:"rgba(139,92,246,0.4)", animation:"spincw 1.8s linear infinite reverse" }} />
        <span style={{ fontSize:26, position:"relative", zIndex:1 }}>🛡</span>
      </div>

      <p style={{ fontWeight:700, fontSize:16, color:"#F1F5F9", marginBottom:6, letterSpacing:"-0.01em" }}>Analysing repository</p>
      <p style={{ fontSize:12, fontFamily:"'Courier New',monospace", color:"#8B5CF6", marginBottom:28, opacity:0.9 }}>
        {repo.replace("https://github.com/","")}
      </p>

      <div style={{ display:"flex", flexDirection:"column", gap:10, maxWidth:300, margin:"0 auto", textAlign:"left" }}>
        {steps.map((s, i) => (
          <div key={s} style={{ display:"flex", alignItems:"center", gap:10, fontSize:12, transition:"all 0.3s",
            color: i < step ? "#10B981" : i === step ? "#F1F5F9" : "#334155" }}>
            <span style={{ fontSize:14, flexShrink:0 }}>
              {i < step ? "✓" : i === step ? "◌" : "○"}
            </span>
            <span style={{ fontFamily: i === step ? "'Courier New',monospace" : "inherit" }}>{s}</span>
            {i === step && (
              <span style={{ marginLeft:"auto", fontSize:10, color:"#8B5CF6", fontFamily:"'Courier New',monospace", animation:"blink 1s step-end infinite" }}>▋</span>
            )}
          </div>
        ))}
      </div>

      <p style={{ fontSize:11, color:"#334155", marginTop:28 }}>Scan may take 30–120s depending on repository size</p>

      <style>{`
        @keyframes scanline { 0%{top:0;opacity:0} 5%{opacity:1} 95%{opacity:1} 100%{top:100%;opacity:0} }
        @keyframes spincw { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
      `}</style>
    </div>
  );
}

function FindingRow({ v, expanded, onToggle, idx }: { v: Vuln; expanded: boolean; onToggle: () => void; idx: number }) {
  const sev = SEV[v.severity] || SEV.INFO;
  const color = riskColor(v.cvss_score);
  return (
    <div style={{ borderBottom:"1px solid rgba(255,255,255,0.04)", transition:"background 0.15s" }}
      onMouseEnter={e => !expanded && (e.currentTarget.style.background="rgba(139,92,246,0.03)")}
      onMouseLeave={e => !expanded && (e.currentTarget.style.background="transparent")}>

      {/* Main row */}
      <div onClick={onToggle} style={{ display:"flex", alignItems:"center", gap:14, padding:"14px 20px", cursor:"pointer" }}>
        <CVSSBadge score={v.cvss_score} />

        <div style={{ flex:1, minWidth:0 }}>
          {/* Badges row */}
          <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:5, flexWrap:"wrap" as const }}>
            <SevBadge s={v.severity} />
            <EngBadge e={v.engine} />
            <CWEBadge cwe={v.cwe} />
            {v.cve_id && (
              <span style={{ fontSize:9, fontFamily:"'Courier New',monospace", fontWeight:700, padding:"2px 6px", borderRadius:3, color:"#8B5CF6", background:"rgba(139,92,246,0.1)", border:"1px solid rgba(139,92,246,0.25)", whiteSpace:"nowrap" as const }}>{v.cve_id}</span>
            )}
          </div>
          {/* Title */}
          <div style={{ fontSize:13, fontWeight:600, color:"#E2E8F0", marginBottom:3, lineHeight:1.3 }}>
            {v.title || "Security Finding"}
          </div>
          {/* File path */}
          <div style={{ fontSize:11, fontFamily:"'Courier New',monospace", color:"#8B5CF6", opacity:0.8 }}>
            {v.file_path}
            <span style={{ color:"#475569" }}>:{v.line_number}</span>
          </div>
        </div>

        {/* Chevron */}
        <div style={{ width:28, height:28, borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center",
          background: expanded ? "rgba(139,92,246,0.15)" : "rgba(255,255,255,0.03)",
          border: `1px solid ${expanded ? "rgba(139,92,246,0.3)" : "rgba(255,255,255,0.06)"}`,
          transition:"all 0.2s", flexShrink:0 }}>
          <span style={{ color:"#64748B", transform: expanded ? "rotate(90deg)" : "none", transition:"transform 0.2s", display:"inline-block", fontSize:14 }}>›</span>
        </div>
      </div>

      {/* Expanded drawer */}
      {expanded && (
        <div style={{ padding:"0 20px 20px", borderTop:"1px solid rgba(255,255,255,0.04)" }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginTop:16, marginBottom:14 }}>
            <div style={{ background:"#07070F", border:"1px solid rgba(255,255,255,0.05)", borderRadius:10, padding:"14px 16px" }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#475569", letterSpacing:"0.08em", marginBottom:8 }}>DESCRIPTION</div>
              <p style={{ fontSize:12.5, lineHeight:1.65, color:"#94A3B8" }}>{v.description || "No description available."}</p>
            </div>
            <div style={{ background:"#07070F", border:"1px solid rgba(16,185,129,0.1)", borderRadius:10, padding:"14px 16px" }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#10B981", letterSpacing:"0.08em", marginBottom:8 }}>REMEDIATION</div>
              <p style={{ fontSize:12.5, lineHeight:1.65, color:"#94A3B8" }}>{v.remediation || "Review the flagged code and apply security best practices."}</p>
            </div>
          </div>

          {/* CVSS slider */}
          <div style={{ background:"#07070F", border:"1px solid rgba(255,255,255,0.05)", borderRadius:10, padding:"12px 16px" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12 }}>
              <span style={{ fontSize:10, fontWeight:700, color:"#475569", letterSpacing:"0.06em", whiteSpace:"nowrap" as const }}>CVSS v3.1</span>
              <div style={{ flex:1, height:5, borderRadius:999, background:"rgba(255,255,255,0.05)", overflow:"hidden", position:"relative" }}>
                {/* Background gradient */}
                <div style={{ position:"absolute", inset:0, background:"linear-gradient(90deg,#3B82F6 0%,#EAB308 40%,#F59E0B 70%,#EF4444 100%)", opacity:0.15 }} />
                {/* Score fill */}
                <div style={{ position:"absolute", left:0, top:0, bottom:0, borderRadius:999,
                  background:`linear-gradient(90deg,${color}80,${color})`,
                  width:`${(v.cvss_score/10)*100}%`,
                  boxShadow:`0 0 8px ${color}80`,
                  transition:"width 0.8s cubic-bezier(0.4,0,0.2,1)" }} />
                {/* Score marker */}
                <div style={{ position:"absolute", top:"50%", transform:"translate(-50%,-50%)",
                  left:`${(v.cvss_score/10)*100}%`,
                  width:10, height:10, borderRadius:"50%", background:color,
                  boxShadow:`0 0 10px ${color}`, border:"2px solid #07070F" }} />
              </div>
              <div style={{ display:"flex", alignItems:"baseline", gap:4, flexShrink:0 }}>
                <span style={{ fontSize:18, fontWeight:900, color, fontFamily:"'Courier New',monospace", textShadow:`0 0 10px ${color}` }}>
                  {v.cvss_score.toFixed(1)}
                </span>
                <span style={{ fontSize:10, color:"#475569" }}>/10</span>
                <span style={{ fontSize:10, fontWeight:700, color, marginLeft:4, letterSpacing:"0.04em" }}>
                  {v.severity}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [tab, setTab]                   = useState<"scan"|"history">("scan");
  const [repoUrl, setRepoUrl]           = useState("");
  const [branch, setBranch]             = useState("main");
  const [minSev, setMinSev]             = useState<string>("INFO");
  const [scanning, setScanning]         = useState(false);
  const [result, setResult]             = useState<ScanResult | null>(null);
  const [history, setHistory]           = useState<ScanHistoryItem[]>([]);
  const [error, setError]               = useState("");
  const [expanded, setExpanded]         = useState<number | null>(null);
  const [filterSev, setFilterSev]       = useState("ALL");
  const [search, setSearch]             = useState("");
  const [collapsed, setCollapsed]       = useState(false);

  useEffect(() => { fetchHistory(); }, []);

  const fetchHistory = useCallback(async () => {
    try { setHistory(await getScanHistory()); } catch {}
  }, []);

  async function handleScan() {
    if (!repoUrl.trim()) return;
    setError(""); setScanning(true); setResult(null); setExpanded(null); setFilterSev("ALL"); setSearch("");
    try {
      const r = await runScan({ repo_url:repoUrl, branch, scan_depth:"full", min_severity:minSev as any });
      setResult(r); fetchHistory();
    } catch (e: any) { setError(e.message); }
    finally { setScanning(false); }
  }

  const findings = result?.vulnerabilities ?? [];
  const filtered = findings.filter(v => {
    if (filterSev !== "ALL" && v.severity !== filterSev) return false;
    if (search) {
      const q = search.toLowerCase();
      return (v.title||"").toLowerCase().includes(q) ||
            (v.file_path||"").toLowerCase().includes(q) ||
            (v.cwe||"").toLowerCase().includes(q) ||
            (v.description||"").toLowerCase().includes(q);
    }
    return true;
  });

  const maxCount = result ? Math.max(...SEVS.map(s => result.summary.severity_breakdown[s]||0), 1) : 1;
  const rc = result ? riskColor(result.summary.risk_score) : "#64748B";

  return (
    <div style={{ minHeight:"100vh", display:"flex", background:"#05050A", fontFamily:"Inter,-apple-system,sans-serif", color:"#E2E8F0" }}>

      {/* ── Background mesh ── */}
      <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0,
        backgroundImage:"linear-gradient(rgba(139,92,246,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(139,92,246,0.03) 1px,transparent 1px)",
        backgroundSize:"32px 32px" }} />
      <div style={{ position:"fixed", top:"20%", left:"40%", width:600, height:600, pointerEvents:"none", zIndex:0,
        background:"radial-gradient(circle,rgba(139,92,246,0.04) 0%,transparent 60%)" }} />

      {/* ── Sidebar ── */}
      <aside style={{ width:collapsed?56:220, background:"rgba(11,11,20,0.95)", borderRight:"1px solid rgba(255,255,255,0.05)",
        display:"flex", flexDirection:"column", transition:"width 0.25s cubic-bezier(0.4,0,0.2,1)",
        flexShrink:0, position:"sticky", top:0, height:"100vh", zIndex:20, backdropFilter:"blur(20px)" }}>

        {/* Brand */}
        <div style={{ padding:"16px 14px", borderBottom:"1px solid rgba(255,255,255,0.05)", display:"flex", alignItems:"center", gap:10 }}>
          {/* Logo mark */}
          <div style={{ width:32, height:32, borderRadius:9, background:"linear-gradient(135deg,#7C3AED,#4F46E5)",
            display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0,
            boxShadow:"0 0 16px rgba(124,58,237,0.4)" }}>
            <svg width={18} height={18} viewBox="0 0 18 18" fill="none">
              <rect x={1} y={1} width={7} height={7} rx={1} fill="rgba(255,255,255,0.9)" />
              <rect x={10} y={1} width={7} height={7} rx={1} fill="rgba(255,255,255,0.4)" />
              <rect x={1} y={10} width={7} height={7} rx={1} fill="rgba(255,255,255,0.4)" />
              <rect x={10} y={10} width={7} height={7} rx={1} fill="rgba(255,255,255,0.7)" />
            </svg>
          </div>
          {!collapsed && (
            <div style={{ overflow:"hidden" }}>
              <div style={{ fontWeight:800, fontSize:14, letterSpacing:"-0.02em", whiteSpace:"nowrap" as const }}>
                Purple<span style={{ color:"#8B5CF6" }}>Grid</span>
              </div>
              <div style={{ fontSize:9, color:"#334155", letterSpacing:"0.1em", fontFamily:"'Courier New',monospace" }}>SECURITY SCANNER</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ padding:"12px 8px", flex:1 }}>
          {[
            { id:"scan",    icon:"⊕", label:"New Scan" },
            { id:"history", icon:"◷", label:`History${history.length?` (${history.length})`:""}`},
          ].map(({id,icon,label}) => (
            <div key={id} onClick={() => { setTab(id as any); if(id==="history") fetchHistory(); }}
              style={{ display:"flex", alignItems:"center", gap:9, padding:"9px 10px", borderRadius:8, marginBottom:2, cursor:"pointer", fontSize:13, fontWeight:500, transition:"all 0.15s",
                color: tab===id ? "#F1F5F9" : "#475569",
                background: tab===id ? "rgba(139,92,246,0.12)" : "transparent",
                border: `1px solid ${tab===id ? "rgba(139,92,246,0.25)" : "transparent"}`,
                justifyContent: collapsed ? "center" : "flex-start",
                boxShadow: tab===id ? "0 0 12px rgba(139,92,246,0.1)" : "none",
              }}>
              <span style={{ fontSize:16, flexShrink:0, color: tab===id ? "#8B5CF6" : "inherit" }}>{icon}</span>
              {!collapsed && <span>{label}</span>}
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding:"10px 8px", borderTop:"1px solid rgba(255,255,255,0.05)" }}>
          {[
            { icon:"◁", label:"Collapse", action:() => setCollapsed(!collapsed) },
            { icon:"⏻", label:"Sign out",  action:onLogout },
          ].map(({icon,label,action}) => (
            <div key={label} onClick={action}
              style={{ display:"flex", alignItems:"center", gap:9, padding:"8px 10px", borderRadius:8, cursor:"pointer", fontSize:12, color:"#334155", transition:"color 0.15s", marginBottom:1, justifyContent:collapsed?"center":"flex-start" }}
              onMouseEnter={e => (e.currentTarget.style.color="#94A3B8")}
              onMouseLeave={e => (e.currentTarget.style.color="#334155")}>
              <span style={{ fontSize:14, flexShrink:0 }}>{icon}</span>
              {!collapsed && <span>{label}</span>}
            </div>
          ))}
        </div>
      </aside>

      {/* ── Main ── */}
      <main style={{ flex:1, display:"flex", flexDirection:"column", minWidth:0, position:"relative", zIndex:1 }}>

        {/* Topbar */}
        <header style={{ height:52, display:"flex", alignItems:"center", justifyContent:"space-between",
          padding:"0 28px", borderBottom:"1px solid rgba(255,255,255,0.05)",
          background:"rgba(5,5,10,0.9)", backdropFilter:"blur(20px)", position:"sticky", top:0, zIndex:40 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <span style={{ fontSize:14, fontWeight:700, color:"#F1F5F9", letterSpacing:"-0.01em" }}>
              {tab==="scan" ? "Vulnerability Scanner" : "Scan History"}
            </span>
            {result && tab==="scan" && (
              <span style={{ fontSize:11, fontFamily:"'Courier New',monospace", fontWeight:700,
                color:"#8B5CF6", background:"rgba(139,92,246,0.1)", border:"1px solid rgba(139,92,246,0.2)",
                padding:"2px 10px", borderRadius:99, letterSpacing:"0.02em" }}>
                {findings.length} findings
              </span>
            )}
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:6, fontSize:11, fontWeight:600,
            color:"#10B981", background:"rgba(16,185,129,0.08)", border:"1px solid rgba(16,185,129,0.15)",
            padding:"5px 12px", borderRadius:99, letterSpacing:"0.02em" }}>
            <div style={{ width:6, height:6, borderRadius:"50%", background:"#10B981", boxShadow:"0 0 6px #10B981" }} />
            API online
          </div>
        </header>

        {/* Content */}
        <div style={{ flex:1, padding:"24px 28px", maxWidth:1120, width:"100%", margin:"0 auto" }}>

          {/* ══ SCAN TAB ══ */}
          {tab==="scan" && (
            <div style={{ display:"flex", flexDirection:"column", gap:18 }}>

              {/* Scan form */}
              <div style={{ background:"#0B0B14", border:"1px solid rgba(139,92,246,0.12)", borderRadius:14, padding:"22px 24px" }}>
                <div style={{ fontSize:13, fontWeight:700, color:"#F1F5F9", marginBottom:16, display:"flex", alignItems:"center", gap:8 }}>
                  <span>🔍</span> Scan a repository
                </div>
                <div style={{ display:"flex", gap:10, flexWrap:"wrap" as const }}>
                  <input type="text" value={repoUrl} onChange={e=>setRepoUrl(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleScan()}
                    placeholder="https://github.com/owner/repository"
                    style={{ flex:1, minWidth:240, padding:"11px 16px", borderRadius:10,
                      background:"#07070F", border:"1px solid rgba(255,255,255,0.07)", color:"#F1F5F9",
                      fontSize:13, fontFamily:"'Courier New',monospace", outline:"none", transition:"border-color 0.2s" }}
                    onFocus={e=>(e.target.style.borderColor="rgba(139,92,246,0.5)")}
                    onBlur={e=>(e.target.style.borderColor="rgba(255,255,255,0.07)")} />
                  <input type="text" value={branch} onChange={e=>setBranch(e.target.value)} placeholder="main"
                    style={{ width:90, padding:"11px 14px", borderRadius:10,
                      background:"#07070F", border:"1px solid rgba(255,255,255,0.07)", color:"#F1F5F9",
                      fontSize:13, fontFamily:"'Courier New',monospace", outline:"none", transition:"border-color 0.2s" }}
                    onFocus={e=>(e.target.style.borderColor="rgba(139,92,246,0.5)")}
                    onBlur={e=>(e.target.style.borderColor="rgba(255,255,255,0.07)")} />
                  <select value={minSev} onChange={e=>setMinSev(e.target.value)}
                    style={{ padding:"11px 14px", borderRadius:10, background:"#07070F", border:"1px solid rgba(255,255,255,0.07)", color:"#F1F5F9", fontSize:12, fontFamily:"'Courier New',monospace", outline:"none" }}>
                    <option value="CRITICAL">CRITICAL+</option>
                    <option value="HIGH">HIGH+</option>
                    <option value="MEDIUM">MEDIUM+</option>
                    <option value="LOW">LOW+</option>
                    <option value="INFO">ALL</option>
                  </select>
                  <button onClick={handleScan} disabled={scanning||!repoUrl.trim()}
                    style={{ padding:"11px 22px", borderRadius:10, border:"none", cursor:scanning||!repoUrl.trim()?"not-allowed":"pointer",
                      background:scanning||!repoUrl.trim()?"#1a1a2e":"linear-gradient(135deg,#7C3AED,#6D28D9)",
                      color:scanning||!repoUrl.trim()?"#334155":"#fff", fontWeight:700, fontSize:13,
                      display:"flex", alignItems:"center", gap:8, transition:"all 0.2s", whiteSpace:"nowrap" as const,
                      boxShadow:scanning||!repoUrl.trim()?"none":"0 0 20px rgba(124,58,237,0.3)" }}>
                    {scanning ? "⟳ Scanning…" : "⚡ Run scan"}
                  </button>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginTop:12, flexWrap:"wrap" as const }}>
                  <span style={{ fontSize:11, color:"#334155" }}>Try:</span>
                  {[["OWASP/WebGoat","master"],["pallets/flask","main"],["django/django","main"]].map(([r,b])=>(
                    <button key={r} onClick={()=>{setRepoUrl(`https://github.com/${r}`);setBranch(b);}}
                      style={{ fontSize:11, fontFamily:"'Courier New',monospace", color:"#475569",
                        background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)",
                        padding:"3px 10px", borderRadius:6, cursor:"pointer", transition:"all 0.15s" }}
                      onMouseEnter={e=>{e.currentTarget.style.color="#8B5CF6";e.currentTarget.style.borderColor="rgba(139,92,246,0.3)";}}
                      onMouseLeave={e=>{e.currentTarget.style.color="#475569";e.currentTarget.style.borderColor="rgba(255,255,255,0.07)";}}>
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              {/* Error */}
              {error && (
                <div style={{ display:"flex", gap:10, padding:"14px 18px", borderRadius:12,
                  background:"rgba(239,68,68,0.06)", border:"1px solid rgba(239,68,68,0.2)", color:"#FCA5A5", fontSize:13 }}>
                  ⚠ {error}
                </div>
              )}

              {/* Scanning */}
              {scanning && <ScanProgress repo={repoUrl} />}

              {/* Results */}
              {result && !scanning && (
                <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

                  {/* KPI row */}
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:14 }}>
                    {[
                      { label:"TOTAL FINDINGS", val:findings.length.toString(), sub:`${filtered.length} shown after filters`, color:"#8B5CF6" },
                      { label:"RISK SCORE", val:result.summary.risk_score.toFixed(2), sub:"CVSS v3.1 weighted avg", color:rc },
                      { label:"SCAN DURATION", val:`${(result.duration_ms/1000).toFixed(1)}s`, sub:`${result.branch} · full scan`, color:"#10B981" },
                    ].map(({label,val,sub,color})=>(
                      <div key={label} style={{ background:"#0B0B14", border:"1px solid rgba(255,255,255,0.05)", borderRadius:14, padding:"20px 22px", position:"relative", overflow:"hidden" }}>
                        <div style={{ position:"absolute", top:0, left:0, right:0, height:2, background:`linear-gradient(90deg,transparent,${color},transparent)`, opacity:0.4 }} />
                        <div style={{ fontSize:10, fontWeight:700, color:"#334155", letterSpacing:"0.1em", marginBottom:10 }}>{label}</div>
                        <div style={{ fontSize:34, fontWeight:900, color, letterSpacing:"-0.03em", lineHeight:1, textShadow:`0 0 20px ${color}40` }}>{val}</div>
                        <div style={{ fontSize:11, color:"#334155", marginTop:5 }}>{sub}</div>
                      </div>
                    ))}
                  </div>

                  {/* Severity breakdown */}
                  <div style={{ background:"#0B0B14", border:"1px solid rgba(255,255,255,0.05)", borderRadius:14, padding:"20px 24px" }}>
                    <div style={{ fontSize:13, fontWeight:700, color:"#F1F5F9", marginBottom:18, display:"flex", alignItems:"center", gap:8 }}>
                      <span>📊</span> Severity breakdown
                    </div>
                    <div style={{ display:"flex", flexDirection:"column", gap:11 }}>
                      {SEVS.map(s => {
                        const count = result.summary.severity_breakdown[s]||0;
                        const c = SEV[s];
                        return (
                          <div key={s} style={{ display:"flex", alignItems:"center", gap:14 }}>
                            <div style={{ width:68, textAlign:"right", flexShrink:0 }}><SevBadge s={s} /></div>
                            <div style={{ flex:1, height:6, borderRadius:999, background:"rgba(255,255,255,0.04)", overflow:"hidden" }}>
                              <div style={{ height:"100%", borderRadius:999, background:c.bar, width:`${(count/maxCount)*100}%`,
                                transition:"width 1.2s cubic-bezier(0.4,0,0.2,1)",
                                boxShadow: count>0 ? `0 0 10px ${c.glow}` : "none" }} />
                            </div>
                            <div style={{ width:36, textAlign:"right", fontSize:13, fontFamily:"'Courier New',monospace", fontWeight:900,
                              color:count>0?c.color:"#1E293B", textShadow:count>0?`0 0 8px ${c.color}60`:"none" }}>
                              {count}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Findings table */}
                  <div style={{ background:"#0B0B14", border:"1px solid rgba(255,255,255,0.05)", borderRadius:14, overflow:"hidden" }}>
                    {/* Table header */}
                    <div style={{ padding:"14px 20px", borderBottom:"1px solid rgba(255,255,255,0.05)", display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" as const }}>
                      <span style={{ fontSize:13, fontWeight:700, color:"#F1F5F9" }}>🛡 Findings</span>
                      <span style={{ fontSize:11, fontFamily:"'Courier New',monospace", color:"#475569",
                        background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.06)",
                        padding:"2px 8px", borderRadius:99 }}>
                        {filtered.length} / {findings.length}
                      </span>
                      <div style={{ flex:1 }} />
                      {/* Search */}
                      <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search findings…"
                        style={{ padding:"6px 12px", borderRadius:8, background:"#07070F",
                          border:"1px solid rgba(255,255,255,0.07)", color:"#E2E8F0", fontSize:12, outline:"none", width:180 }}
                        onFocus={e=>(e.target.style.borderColor="rgba(139,92,246,0.4)")}
                        onBlur={e=>(e.target.style.borderColor="rgba(255,255,255,0.07)")} />
                      {/* Filter pills */}
                      <div style={{ display:"flex", gap:4, flexWrap:"wrap" as const }}>
                        {["ALL",...SEVS].map(s => {
                          const c = SEV[s as string];
                          const active = filterSev===s;
                          return (
                            <button key={s} onClick={()=>setFilterSev(s)}
                              style={{ fontSize:9, fontFamily:"'Courier New',monospace", fontWeight:800, padding:"4px 9px", borderRadius:5, cursor:"pointer", transition:"all 0.15s",
                                color:active?(s==="ALL"?"#fff":c?.color||"#fff"):"#334155",
                                background:active?(s==="ALL"?"#7C3AED":c?.bg||"#1a1a2e"):"transparent",
                                border:`1px solid ${active?(s==="ALL"?"#7C3AED":c?.border||"#334155"):"rgba(255,255,255,0.06)"}`,
                                boxShadow:active&&s!=="ALL"?`0 0 8px ${c?.glow}`:"none",
                              }}>
                              {s}
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    {/* Rows */}
                    <div>
                      {filtered.length===0 ? (
                        <div style={{ padding:"56px", textAlign:"center", color:"#1E293B", fontSize:13 }}>
                          No findings match the current filters
                        </div>
                      ) : filtered.map((v,i)=>(
                        <FindingRow key={i} v={v as Vuln} idx={i} expanded={expanded===i} onToggle={()=>setExpanded(expanded===i?null:i)} />
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Empty state */}
              {!result && !scanning && !error && (
                <div style={{ background:"#0B0B14", border:"1px solid rgba(255,255,255,0.05)", borderRadius:14, padding:"72px 32px", textAlign:"center" }}>
                  <div style={{ width:60, height:60, borderRadius:16, background:"rgba(139,92,246,0.08)", border:"1px solid rgba(139,92,246,0.12)", display:"flex", alignItems:"center", justifyContent:"center", margin:"0 auto 18px", fontSize:26 }}>🔍</div>
                  <p style={{ fontSize:16, fontWeight:700, color:"#F1F5F9", marginBottom:8, letterSpacing:"-0.01em" }}>Ready to scan</p>
                  <p style={{ fontSize:13, color:"#334155", maxWidth:380, margin:"0 auto", lineHeight:1.6 }}>
                    Enter a public GitHub repository URL and click Run scan to detect real vulnerabilities using Bandit and Semgrep static analysis engines.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* ══ HISTORY TAB ══ */}
          {tab==="history" && (
            <div style={{ background:"#0B0B14", border:"1px solid rgba(255,255,255,0.05)", borderRadius:14, overflow:"hidden" }}>
              <div style={{ padding:"16px 20px", borderBottom:"1px solid rgba(255,255,255,0.05)", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <span style={{ fontSize:13, fontWeight:700, color:"#F1F5F9" }}>◷ Scan history</span>
                  <span style={{ fontSize:11, fontFamily:"'Courier New',monospace", color:"#475569", background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.06)", padding:"2px 8px", borderRadius:99 }}>
                    {history.length} scans
                  </span>
                </div>
                <div style={{ display:"flex", gap:8 }}>
                  <button onClick={fetchHistory}
                    style={{ fontSize:12, color:"#475569", background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.07)", padding:"6px 14px", borderRadius:8, cursor:"pointer", transition:"color 0.15s" }}
                    onMouseEnter={e=>(e.currentTarget.style.color="#E2E8F0")} onMouseLeave={e=>(e.currentTarget.style.color="#475569")}>
                    ⟳ Refresh
                  </button>
                  <button onClick={()=>setTab("scan")}
                    style={{ fontSize:12, color:"#fff", background:"linear-gradient(135deg,#7C3AED,#6D28D9)", border:"none", padding:"6px 16px", borderRadius:8, cursor:"pointer", fontWeight:700, boxShadow:"0 0 14px rgba(124,58,237,0.3)" }}>
                    + New scan
                  </button>
                </div>
              </div>

              {history.length===0 ? (
                <div style={{ padding:"72px", textAlign:"center", color:"#1E293B", fontSize:13 }}>No scans yet</div>
              ) : history.map((s,i)=>{
                const rc = s.risk_score!=null?(s.risk_score>=7?"#EF4444":s.risk_score>=4?"#EAB308":"#10B981"):"#475569";
                return (
                  <div key={i} style={{ display:"flex", alignItems:"center", gap:16, padding:"14px 20px", borderBottom:"1px solid rgba(255,255,255,0.04)", transition:"background 0.15s" }}
                    onMouseEnter={e=>(e.currentTarget.style.background="rgba(139,92,246,0.03)")}
                    onMouseLeave={e=>(e.currentTarget.style.background="transparent")}>
                    <div style={{ width:36, height:36, borderRadius:10, background:"rgba(139,92,246,0.08)", border:"1px solid rgba(139,92,246,0.15)", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, fontSize:16 }}>🛡</div>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ fontSize:13, fontFamily:"'Courier New',monospace", color:"#E2E8F0", fontWeight:600, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" as const }}>
                        {s.repo_url.replace("https://github.com/","")}
                      </div>
                      <div style={{ display:"flex", alignItems:"center", gap:8, marginTop:4 }}>
                        <span style={{ fontSize:11, color:"#334155" }}>
                          {new Date(s.created_at).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit"})}
                        </span>
                        <span style={{ fontSize:10, fontFamily:"'Courier New',monospace", color:"#334155", background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.06)", padding:"1px 6px", borderRadius:3 }}>
                          {s.branch}
                        </span>
                        <span style={{ fontSize:10, fontWeight:700, color:"#10B981", background:"rgba(16,185,129,0.08)", border:"1px solid rgba(16,185,129,0.2)", padding:"1px 6px", borderRadius:3, fontFamily:"'Courier New',monospace" }}>
                          {(s.status||"completed").toUpperCase()}
                        </span>
                      </div>
                    </div>
                    <div style={{ textAlign:"right", flexShrink:0 }}>
                      <div style={{ fontSize:18, fontWeight:900, color:rc, fontFamily:"'Courier New',monospace", textShadow:`0 0 10px ${rc}60` }}>
                        {s.risk_score!=null?s.risk_score.toFixed(2):"—"}
                      </div>
                      <div style={{ fontSize:11, color:"#334155" }}>{s.total_vulns??0} findings</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}