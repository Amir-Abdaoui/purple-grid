"use client";
import { useState, useEffect } from "react";
import { runScan, getScanHistory, ScanResult, ScanHistoryItem } from "@/lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-900/30 border-red-700",
  HIGH: "text-orange-400 bg-orange-900/30 border-orange-700",
  MEDIUM: "text-yellow-400 bg-yellow-900/30 border-yellow-700",
  LOW: "text-blue-400 bg-blue-900/30 border-blue-700",
  INFO: "text-gray-400 bg-gray-800 border-gray-600",
};

const SEVERITY_BAR: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-blue-500",
  INFO: "bg-gray-500",
};

export default function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [minSeverity, setMinSeverity] = useState<"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO">("MEDIUM");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"scan"|"history">("scan");

  useEffect(() => {
    fetchHistory();
  }, []);

  async function fetchHistory() {
    try {
      const h = await getScanHistory();
      setHistory(h);
    } catch {}
  }

  async function handleScan() {
    if (!repoUrl) return;
    setError("");
    setScanning(true);
    setResult(null);
    try {
      const r = await runScan({
        repo_url: repoUrl,
        branch,
        scan_depth: "full",
        min_severity: minSeverity,
      });
      setResult(r);
      fetchHistory();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setScanning(false);
    }
  }

  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const maxCount = result
    ? Math.max(...severities.map((s) => result.summary.severity_breakdown[s] || 0), 1)
    : 1;

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-2.5 h-2.5 rounded-full bg-purple-500" />
            <span className="font-bold text-white">purple-grid</span>
            <span className="text-gray-600 text-sm">/ vulnerability scanner</span>
          </div>
          <button
            onClick={onLogout}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            Sign out
          </button>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Tabs */}
        <div className="flex gap-1 mb-8 bg-gray-900 rounded-lg p-1 w-fit">
          <button
            onClick={() => setActiveTab("scan")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === "scan" ? "bg-purple-600 text-white" : "text-gray-400 hover:text-white"
            }`}
          >
            New scan
          </button>
          <button
            onClick={() => { setActiveTab("history"); fetchHistory(); }}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === "history" ? "bg-purple-600 text-white" : "text-gray-400 hover:text-white"
            }`}
          >
            History {history.length > 0 && `(${history.length})`}
          </button>
        </div>

        {activeTab === "scan" && (
          <div className="space-y-6">
            {/* Scan form */}
            <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
              <h2 className="text-white font-semibold mb-4">Scan a repository</h2>
              <div className="flex gap-3 flex-wrap">
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleScan()}
                  placeholder="https://github.com/owner/repo"
                  className="flex-1 min-w-64 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500 font-mono"
                />
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className="w-28 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500"
                />
                <select
                  value={minSeverity}
                  onChange={(e) => setMinSeverity(e.target.value as any)}
                  className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500"
                >
                  <option value="CRITICAL">CRITICAL+</option>
                  <option value="HIGH">HIGH+</option>
                  <option value="MEDIUM">MEDIUM+</option>
                  <option value="LOW">LOW+</option>
                  <option value="INFO">ALL</option>
                </select>
                <button
                  onClick={handleScan}
                  disabled={scanning || !repoUrl}
                  className="bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-medium px-6 py-2.5 rounded-lg transition-colors text-sm whitespace-nowrap"
                >
                  {scanning ? "Scanning..." : "Run scan"}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-red-900/40 border border-red-700 rounded-xl px-5 py-4 text-red-400 text-sm">
                {error}
              </div>
            )}

            {scanning && (
              <div className="bg-gray-900 rounded-2xl p-8 border border-gray-800 text-center">
                <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
                <p className="text-gray-400 text-sm">Cloning repository and running Bandit + Semgrep...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                {/* Summary cards */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
                    <div className="text-3xl font-bold text-white">{result.summary.total_vulnerabilities}</div>
                    <div className="text-gray-400 text-sm mt-1">Total findings</div>
                  </div>
                  <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
                    <div className={`text-3xl font-bold ${result.summary.risk_score >= 7 ? "text-red-400" : result.summary.risk_score >= 4 ? "text-yellow-400" : "text-green-400"}`}>
                      {result.summary.risk_score}
                    </div>
                    <div className="text-gray-400 text-sm mt-1">Risk score</div>
                  </div>
                  <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
                    <div className="text-3xl font-bold text-white">{(result.duration_ms / 1000).toFixed(1)}s</div>
                    <div className="text-gray-400 text-sm mt-1">Scan duration</div>
                  </div>
                </div>

                {/* Severity breakdown */}
                <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
                  <h3 className="text-white font-medium mb-4">Severity breakdown</h3>
                  <div className="space-y-3">
                    {severities.map((s) => {
                      const count = result.summary.severity_breakdown[s] || 0;
                      return (
                        <div key={s} className="flex items-center gap-3">
                          <div className="w-20 text-right">
                            <span className={`text-xs font-mono font-medium px-2 py-0.5 rounded border ${SEVERITY_COLOR[s]}`}>
                              {s}
                            </span>
                          </div>
                          <div className="flex-1 bg-gray-800 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full transition-all duration-500 ${SEVERITY_BAR[s]}`}
                              style={{ width: `${(count / maxCount) * 100}%` }}
                            />
                          </div>
                          <div className="w-6 text-right text-white text-sm font-mono">{count}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Findings list */}
                <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
                  <div className="px-5 py-4 border-b border-gray-800">
                    <h3 className="text-white font-medium">Findings</h3>
                  </div>
                  <div className="divide-y divide-gray-800">
                    {result.vulnerabilities.map((v, i) => (
                      <div key={i} className="px-5 py-4">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1 flex-wrap">
                              <span className={`text-xs font-mono px-2 py-0.5 rounded border ${SEVERITY_COLOR[v.severity]}`}>
                                {v.severity}
                              </span>
                              <span className="text-white text-sm font-medium">{v.title}</span>
                              <span className="text-gray-500 text-xs font-mono">CWE-{v.cwe}</span>
                            </div>
                            <p className="text-gray-400 text-sm mb-2">{v.description}</p>
                            <div className="font-mono text-xs text-purple-400">
                              {v.file_path}:{v.line_number}
                            </div>
                          </div>
                          <div className="text-right shrink-0">
                            <div className="text-white font-bold">{v.cvss_score}</div>
                            <div className="text-gray-500 text-xs">CVSS</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "history" && (
          <div className="bg-gray-900 rounded-2xl border border-gray-800 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-800">
              <h3 className="text-white font-medium">Scan history</h3>
            </div>
            {history.length === 0 ? (
              <div className="px-5 py-12 text-center text-gray-500 text-sm">No scans yet</div>
            ) : (
              <div className="divide-y divide-gray-800">
                {history.map((scan) => (
                  <div key={scan.id} className="px-5 py-4 flex items-center justify-between gap-4">
                    <div>
                      <div className="text-white text-sm font-mono truncate max-w-md">{scan.repo_url}</div>
                      <div className="text-gray-500 text-xs mt-1">
                        {new Date(scan.created_at).toLocaleString()} · {scan.branch}
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className={`text-sm font-bold ${scan.risk_score >= 7 ? "text-red-400" : scan.risk_score >= 4 ? "text-yellow-400" : "text-green-400"}`}>
                        {scan.risk_score} risk
                      </div>
                      <div className="text-gray-500 text-xs">{scan.total_vulns} findings</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}