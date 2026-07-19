const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://purple-grid-api.onrender.com";

export interface ScanRequest {
  repo_url: string;
  branch: string;
  scan_depth: "shallow" | "full";
  min_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
}

export interface Vulnerability {
  finding_id: string;
  engine: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss_score: number;
  cwe: string;
  file_path: string;
  line_number: number;
  title: string;
  description: string;
}

export interface ScanResult {
  scan_id: string;
  status: string;
  repo_url: string;
  branch: string;
  scanned_at: string;
  duration_ms: number;
  summary: {
    total_vulnerabilities: number;
    severity_breakdown: Record<string, number>;
    risk_score: number;
  };
  vulnerabilities: Vulnerability[];
}

export interface ScanHistoryItem {
  id: string;
  repo_url: string;
  branch: string;
  status: string;
  risk_score: number;
  total_vulns: number;
  created_at: string;
}

function getToken(): string | null {
  return localStorage.getItem("pg_token");
}

export function saveToken(token: string) {
  localStorage.setItem("pg_token", token);
}

export function clearToken() {
  localStorage.removeItem("pg_token");
}

export function isLoggedIn(): boolean {
  return !!getToken();
}

export async function register(email: string, password: string) {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Registration failed");
  }
  return res.json();
}

export async function login(email: string, password: string): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Login failed");
  }
  const data = await res.json();
  return data.access_token;
}

export async function runScan(request: ScanRequest): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/api/v1/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getToken()}`,
    },
    body: JSON.stringify(request),
  });
  if (res.status === 401) {
    clearToken();
    throw new Error("Session expired. Please log in again.");
  }
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Scan failed");
  }
  return res.json();
}

export async function getScanHistory(): Promise<ScanHistoryItem[]> {
  const res = await fetch(`${API_BASE}/api/v1/scans`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!res.ok) throw new Error("Failed to fetch scan history");
  return res.json();
}