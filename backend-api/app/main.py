"""
Purple-Grid — AI-Powered Vulnerability Scanner API
Backend Microservice · Phase 1 Stub

Security posture:
- No secrets in source; all config injected via environment variables.
- Structured JSON logging for SIEM ingestion.
- Health & readiness probes for container orchestration (Kubernetes / ECS).
"""

from __future__ import annotations

import logging
import os
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, field_validator

# ---------------------------------------------------------------------------
# Structured logging — output to stdout so the container runtime captures it.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("purple-grid")

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Purple-Grid Vulnerability Scanner API",
    description="AI-powered vulnerability analysis microservice.",
    version="1.0.0",
    # Disable docs in production — expose only in non-prod environments.
    docs_url="/docs" if os.getenv("ENV", "production") != "production" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("ENV", "production") != "production" else None,
)

# ---------------------------------------------------------------------------
# CORS — lock to explicit origins; never use wildcard in production.
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas  (Pydantic v2)
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    repo_url: HttpUrl
    branch: str = "main"
    scan_depth: Literal["shallow", "full"] = "full"

    @field_validator("branch")
    @classmethod
    def branch_no_traversal(cls, v: str) -> str:
        """Reject path-traversal attempts in the branch field."""
        if ".." in v or "/" in v:
            raise ValueError("Branch name must not contain path traversal sequences.")
        return v


class Vulnerability(BaseModel):
    cve_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cvss_score: float
    file_path: str
    line_number: int
    description: str
    remediation: str


class ScanResult(BaseModel):
    scan_id: str
    status: Literal["completed", "failed", "pending"]
    repo_url: str
    branch: str
    scanned_at: str
    duration_ms: int
    summary: dict
    vulnerabilities: list[Vulnerability]


# ---------------------------------------------------------------------------
# Mock scan engine — replace with real ML inference in Phase 2.
# ---------------------------------------------------------------------------
_MOCK_VULNS: list[dict] = [
    {
        "cve_id": "CVE-2023-44487",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "file_path": "src/server/http2_handler.py",
        "line_number": 142,
        "description": "HTTP/2 Rapid Reset Attack allows resource exhaustion via stream cancellation.",
        "remediation": "Upgrade to a patched HTTP/2 library version or apply server-side rate limiting on RESET frames.",
    },
    {
        "cve_id": "CVE-2024-3094",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "file_path": "build/scripts/liblzma_hook.c",
        "line_number": 87,
        "description": "XZ Utils supply-chain backdoor enabling remote code execution via compromised liblzma.",
        "remediation": "Pin dependency to xz-utils 5.4.x; audit all build scripts for injected hooks.",
    },
    {
        "cve_id": "CVE-2023-29197",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "file_path": "api/validators.py",
        "line_number": 33,
        "description": "Improper header parsing allows HTTP header injection via unescaped newline characters.",
        "remediation": "Sanitize all user-controlled values before embedding into HTTP response headers.",
    },
    {
        "cve_id": "CVE-2022-42889",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "file_path": "utils/template_engine.py",
        "line_number": 201,
        "description": "Text4Shell: unsafe variable interpolation in Apache Commons Text enables RCE.",
        "remediation": "Upgrade commons-text to >= 1.10.0; avoid StringSubstitutor with untrusted input.",
    },
    {
        "cve_id": "CVE-2023-50164",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "file_path": "controllers/upload_controller.py",
        "line_number": 58,
        "description": "Apache Struts2 path traversal via file upload parameter allows arbitrary file write.",
        "remediation": "Upgrade Struts2 to >= 6.3.0.2; validate and restrict upload directory paths.",
    },
    {
        "cve_id": "CVE-2023-46604",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "file_path": "messaging/activemq_consumer.py",
        "line_number": 17,
        "description": "Apache ActiveMQ RCE via ClassInfo deserialization of untrusted OpenWire protocol data.",
        "remediation": "Upgrade ActiveMQ to >= 5.15.16 or apply vendor patch; restrict broker access by IP.",
    },
    {
        "cve_id": "CVE-2024-21626",
        "severity": "HIGH",
        "cvss_score": 8.6,
        "file_path": "Dockerfile",
        "line_number": 3,
        "description": "runc container escape: working directory leaks host file descriptor enabling breakout.",
        "remediation": "Upgrade runc to >= 1.1.12; apply OCI runtime patches from container vendor.",
    },
    {
        "cve_id": "CVE-2023-38545",
        "severity": "HIGH",
        "cvss_score": 9.8,
        "file_path": "deps/libcurl/socks5.c",
        "line_number": 310,
        "description": "libcurl SOCKS5 heap overflow during hostname resolution when CURLOPT_BUFFERSIZE is set.",
        "remediation": "Upgrade libcurl to >= 8.4.0; avoid SOCKS5 proxies with untrusted hostnames.",
    },
]


def _run_mock_scan(repo_url: str, branch: str, scan_depth: str) -> tuple[list[Vulnerability], int]:
    """
    Simulates ML scan latency and non-deterministic finding counts.
    Phase 2 will wire this to the real inference engine.
    """
    start = time.time()

    # Simulate variable scan latency (50–400 ms)
    time.sleep(random.uniform(0.05, 0.4))

    sample_size = len(_MOCK_VULNS) if scan_depth == "full" else len(_MOCK_VULNS) // 2
    findings = [Vulnerability(**v) for v in random.sample(_MOCK_VULNS, k=random.randint(2, sample_size))]

    duration_ms = int((time.time() - start) * 1000)
    return findings, duration_ms


# ---------------------------------------------------------------------------
# Middleware — attach a correlation ID to every request for distributed tracing.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/healthz", include_in_schema=False)
async def liveness():
    """Kubernetes liveness probe — returns 200 if the process is alive."""
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
async def readiness():
    """
    Kubernetes readiness probe — in Phase 2 this will verify DB connectivity
    and ML model load status before accepting traffic.
    """
    return {"status": "ready", "version": "1.0.0"}


@app.post(
    "/api/v1/scan",
    response_model=ScanResult,
    status_code=status.HTTP_200_OK,
    summary="Submit a repository for vulnerability analysis",
)
async def scan_repository(payload: ScanRequest, request: Request):
    """
    Accepts a Git repository URL and returns a structured vulnerability report.

    - **repo_url**: Fully-qualified HTTPS URL of the target repository.
    - **branch**: Target branch (default: `main`).
    - **scan_depth**: `shallow` (fast, top-level files) or `full` (deep AST + dependency graph).
    """
    scan_id = str(uuid.uuid4())
    logger.info(
        f"scan_started scan_id={scan_id} repo={payload.repo_url} branch={payload.branch}"
    )

    try:
        findings, duration_ms = _run_mock_scan(
            str(payload.repo_url), payload.branch, payload.scan_depth
        )
    except Exception as exc:
        logger.error(f"scan_failed scan_id={scan_id} error={exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan engine encountered an internal error.",
        )

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in findings:
        severity_counts[v.severity] += 1

    result = ScanResult(
        scan_id=scan_id,
        status="completed",
        repo_url=str(payload.repo_url),
        branch=payload.branch,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=duration_ms,
        summary={
            "total_vulnerabilities": len(findings),
            "severity_breakdown": severity_counts,
            "risk_score": round(
                sum(v.cvss_score for v in findings) / max(len(findings), 1), 2
            ),
        },
        vulnerabilities=findings,
    )

    logger.info(
        f"scan_completed scan_id={scan_id} total={len(findings)} duration_ms={duration_ms}"
    )
    return result


# ---------------------------------------------------------------------------
# Global exception handler — never leak stack traces to the client.
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"unhandled_exception path={request.url.path} error={exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."},
    )