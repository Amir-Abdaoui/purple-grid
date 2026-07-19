"""
Purple-Grid â€” AI-Powered Vulnerability Scanner API
Phase 1A: Alembic migrations + clean module separation
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, AsyncGenerator
from concurrent.futures import ThreadPoolExecutor

import asyncio
import bcrypt
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, HttpUrl, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db, engine
from app.models import User, ScanResult as ScanResultModel
from app.scanner import run_real_scan

# â”€â”€ Logging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("purple-grid")

# â”€â”€ Security â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

bearer_scheme = HTTPBearer()
_scan_executor = ThreadPoolExecutor(max_workers=4)

# â”€â”€ App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = FastAPI(
    title="Purple-Grid Vulnerability Scanner API",
    version="4.1.0",
    docs_url="/docs" if os.getenv("ENV") != "production" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("ENV") != "production" else None,
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

def _run_migrations() -> None:
    """Run Alembic migrations synchronously at startup."""
    try:
        alembic_cfg = AlembicConfig("/app/alembic.ini")
        alembic_cfg.set_main_option("script_location", "/app/alembic")
        command.upgrade(alembic_cfg, "head")
        logger.info("alembic_migrations_applied")
    except Exception as e:
        logger.error(f"alembic_migration_failed error={e}")
        raise
# â”€â”€ Startup: run Alembic migrations automatically â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.on_event("startup")
async def startup() -> None:
    # Run migrations synchronously in a thread (Alembic is sync)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run_migrations)

    # Verify connection
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    logger.info("database_ready")





# â”€â”€ Schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ScanRequest(BaseModel):
    repo_url: HttpUrl
    branch: str = "main"
    scan_depth: Literal["shallow", "full"] = "full"
    min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "INFO"

    @field_validator("branch")
    @classmethod
    def branch_no_traversal(cls, v: str) -> str:
        if ".." in v or "/" in v:
            raise ValueError("Branch name must not contain path traversal sequences.")
        return v


class Vulnerability(BaseModel):
    finding_id: str
    engine: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cvss_score: float
    cwe: str
    file_path: str
    line_number: int
    title: str
    description: str
    remediation: str
    cve_id: str | None = None


class ScanResultSchema(BaseModel):
    scan_id: str
    status: Literal["completed", "failed", "pending"]
    repo_url: str
    branch: str
    scanned_at: str
    duration_ms: int
    summary: dict
    vulnerabilities: list[Vulnerability]


class ScanHistoryItem(BaseModel):
    scan_id: str
    repo_url: str
    branch: str
    status: str
    risk_score: float | None
    total_vulns: int | None
    created_at: str
    completed_at: str | None


# â”€â”€ Auth helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)},
        SECRET_KEY, algorithm=ALGORITHM,
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.",
                            headers={"WWW-Authenticate": "Bearer"})
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid token.")
    return user


# â”€â”€ Middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    rid = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


# â”€â”€ Auth routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/auth/register", status_code=201)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    db.add(User(email=payload.email, hashed_password=hash_password(payload.password)))
    await db.flush()
    logger.info(f"user_registered email={payload.email}")
    return {"message": "Account created successfully."}


@app.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning(f"login_failed email={payload.email}")
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    token = create_access_token(subject=user.email)
    logger.info(f"login_success email={payload.email}")
    return TokenResponse(access_token=token, expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)


# â”€â”€ Scan routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/v1/scan", response_model=ScanResultSchema)
async def scan_repository(
    payload: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())
    logger.info(f"scan_started scan_id={scan_id} user={current_user.email} repo={payload.repo_url}")

    try:
        loop = asyncio.get_event_loop()
        raw_findings, duration_ms = await loop.run_in_executor(
            _scan_executor, run_real_scan,
            str(payload.repo_url), payload.branch, payload.scan_depth, payload.min_severity,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error(f"scan_failed scan_id={scan_id} error={exc}")
        raise HTTPException(status_code=500, detail="Scan engine encountered an internal error.")

    findings = [Vulnerability(finding_id=str(uuid.uuid4()), **f) for f in raw_findings]
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in findings:
        sev_counts[v.severity] += 1

    risk_score = round(sum(v.cvss_score for v in findings) / max(len(findings), 1), 2) if findings else 0.0
    scanned_at = datetime.now(timezone.utc)

    db.add(ScanResultModel(
        id=uuid.UUID(scan_id),
        user_id=current_user.id,
        repo_url=str(payload.repo_url),
        branch=payload.branch,
        scan_depth=payload.scan_depth,
        status="completed",
        risk_score=risk_score,
        total_vulns=len(findings),
        raw_payload={
            "summary": {"total_vulnerabilities": len(findings), "severity_breakdown": sev_counts, "risk_score": risk_score},
            "vulnerabilities": [v.model_dump() for v in findings],
        },
        created_at=scanned_at,
        completed_at=scanned_at,
    ))
    await db.flush()
    logger.info(f"scan_completed scan_id={scan_id} total={len(findings)}")

    return ScanResultSchema(
        scan_id=scan_id, status="completed",
        repo_url=str(payload.repo_url), branch=payload.branch,
        scanned_at=scanned_at.isoformat(), duration_ms=duration_ms,
        summary={"total_vulnerabilities": len(findings), "severity_breakdown": sev_counts, "risk_score": risk_score},
        vulnerabilities=findings,
    )


@app.get("/api/v1/scans", response_model=list[ScanHistoryItem])
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResultModel)
        .where(ScanResultModel.user_id == current_user.id)
        .order_by(ScanResultModel.created_at.desc())
        .limit(50)
    )
    return [
        ScanHistoryItem(
            scan_id=str(s.id), repo_url=s.repo_url, branch=s.branch, status=s.status,
            risk_score=float(s.risk_score) if s.risk_score else None,
            total_vulns=s.total_vulns,
            created_at=s.created_at.isoformat(),
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
        )
        for s in result.scalars().all()
    ]


# â”€â”€ Health â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/healthz", include_in_schema=False)
async def liveness(): return {"status": "ok"}

@app.get("/readyz", include_in_schema=False)
async def readiness(): return {"status": "ready", "version": "4.1.0"}


# â”€â”€ Global error handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"unhandled_exception path={request.url.path} error={exc}")
    return JSONResponse(status_code=500, content={"detail": "An unexpected error occurred."})

