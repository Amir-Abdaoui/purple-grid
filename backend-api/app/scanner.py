"""Real static-analysis scan engine for Purple-Grid.

Fetches a public GitHub repo as a tarball (no git binary required — keeps the
hardened runtime image minimal), extracts to tmpfs, runs Bandit + Semgrep,
normalises findings to a stable severity/CVSS model, and guarantees cleanup.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import tempfile
import httpx

logger = logging.getLogger("purple-grid.scanner")

# --- Hard limits: DoS / zip-bomb / abuse protection ------------------------
MAX_ARCHIVE_BYTES = 40 * 1024 * 1024        # reject repos > 40 MB compressed
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024  # reject decompression bombs
DOWNLOAD_TIMEOUT = 30.0
SCAN_TIMEOUT = 120.0

tmp_dir = tempfile.mkdtemp()                        # only writable path (tmpfs)

# --- SSRF protection: GitHub only ------------------------------------------
_ALLOWED_HOSTS = {"github.com", "www.github.com"}
_REPO_RE = re.compile(r"^/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
_CODELOAD = "https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"

# Static analysers surface CWE-class weaknesses, not CVEs. Honest model:
# rule_id + cwe, mapped to a representative CVSS base score.
_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}


class ScanError(Exception):
    """User-correctable failure (bad URL, repo too big, timeout). -> HTTP 400."""


def _parse_github_url(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url.strip())
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
        raise ScanError("Only https://github.com repositories are allowed.")
    m = _REPO_RE.match(parsed.path)
    if not m:
        raise ScanError("URL must be https://github.com/<owner>/<repo>.")
    return m.group(1), m.group(2)


def _safe_branch(branch: str) -> str:
    # Branch goes into a URL — block traversal / injection.
    if not branch or ".." in branch or not re.fullmatch(r"[\w./-]{1,255}", branch):
        raise ScanError("Invalid branch name.")
    return branch


async def _download_repo(owner: str, repo: str, ref: str, dest: Path) -> None:
    url = _CODELOAD.format(owner=owner, repo=repo, ref=ref)
    archive = dest / "repo.tar.gz"
    async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            if resp.status_code == 404:
                raise ScanError("Repository or branch not found (must be public).")
            resp.raise_for_status()
            size = 0
            with archive.open("wb") as fh:
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES:
                        raise ScanError("Repository archive exceeds size limit.")
                    fh.write(chunk)
    _safe_extract(archive, dest)
    archive.unlink(missing_ok=True)


def _safe_extract(archive: Path, dest: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        total = sum(m.size for m in tar.getmembers())
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ScanError("Uncompressed repository too large.")
        # filter="data" (Python 3.12+) blocks path traversal + symlink escape.
        tar.extractall(dest, filter="data")


async def _run(cmd: list[str], cwd: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=cwd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        raise ScanError("Scan timed out.")
    if err and not out:
        logger.warning("scanner_stderr", extra={"cmd": cmd[0], "stderr": err.decode("utf-8", "replace")[:500]})
    return out.decode("utf-8", "replace")


def _rel(path: str, target: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target.resolve()))
    except Exception:
        return path


def _finding(*, engine, rule_id, severity, file_path, line, title, description, cwe):
    return {
        "finding_id": rule_id,          # a static-analysis rule id, NOT a CVE
        "engine": engine,
        "severity": severity,
        "cvss_score": _CVSS[severity],
        "cwe": str(cwe) if cwe else None,
        "file_path": file_path,
        "line_number": line,
        "title": title,
        "description": (description or "")[:1000],
    }


def _bandit_severity(sev: str | None, conf: str | None) -> str:
    sev = (sev or "LOW").upper()
    conf = (conf or "LOW").upper()
    if sev == "HIGH" and conf == "HIGH":
        return "CRITICAL"
    return sev if sev in _CVSS else "LOW"


async def _run_bandit(target: Path) -> list[dict]:
    # bandit exits 1 when it FINDS issues — that's success. We parse stdout.
    out = await _run(["bandit", "-r", str(target), "-f", "json", "-q"], cwd=str(target))
    if not out:
        return []
    data = json.loads(out)
    findings = []
    for r in data.get("results", []):
        findings.append(_finding(
            engine="bandit",
            rule_id=r.get("test_id", "B000"),
            severity=_bandit_severity(r.get("issue_severity"), r.get("issue_confidence")),
            file_path=_rel(r.get("filename", ""), target),
            line=r.get("line_number", 0),
            title=r.get("test_name", ""),
            description=r.get("issue_text", ""),
            cwe=(r.get("issue_cwe") or {}).get("id"),
        ))
    return findings


def _semgrep_severity(sev: str | None) -> str:
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get((sev or "INFO").upper(), "LOW")


async def _run_semgrep(target: Path) -> list[dict]:
    out = await _run(
        ["semgrep", "scan", "--config", "auto", "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(target)],
        cwd=str(target),
    )
    if not out:
        return []
    data = json.loads(out)
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        findings.append(_finding(
            engine="semgrep",
            rule_id=r.get("check_id", "semgrep.rule"),
            severity=_semgrep_severity(extra.get("severity")),
            file_path=_rel(r.get("path", ""), target),
            line=(r.get("start") or {}).get("line", 0),
            title=r.get("check_id", ""),
            description=extra.get("message", ""),
            cwe=cwe,
        ))
    return findings


async def run_scan(repo_url: str, branch: str = "main", scan_depth: str = "full") -> dict:
    started = time.perf_counter()
    scan_id = str(uuid.uuid4())
    owner, repo = _parse_github_url(repo_url)
    ref = _safe_branch(branch)

    workdir = Path(tempfile.mkdtemp(prefix="pg-scan-", dir=TMP_ROOT))
    try:
        await _download_repo(owner, repo, ref, workdir)
        subdirs = [p for p in workdir.iterdir() if p.is_dir()]
        target = subdirs[0] if subdirs else workdir

        bandit, semgrep = await asyncio.gather(_run_bandit(target), _run_semgrep(target))
        findings = bandit + semgrep

        breakdown = {k: 0 for k in _CVSS}
        for f in findings:
            breakdown[f["severity"]] += 1
        risk = max((f["cvss_score"] for f in findings), default=0.0)

        logger.info("scan_completed", extra={
            "scan_id": scan_id, "repo_url": repo_url, "branch": ref,
            "total": len(findings), "risk_score": risk,
        })
        return {
            "scan_id": scan_id,
            "status": "completed",
            "repo_url": repo_url,
            "branch": ref,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "summary": {
                "total_vulnerabilities": len(findings),
                "severity_breakdown": breakdown,
                "risk_score": risk,
            },
            "vulnerabilities": findings,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)   # no disk leaks — guaranteed