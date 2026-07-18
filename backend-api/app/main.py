"""
Purple-Grid — AI-Powered Vulnerability Scanner API
Backend Microservice · Phase 3 — PostgreSQL Persistence
"""

from __future__ import annotations

import logging
import os
import random
import time
import uuid
from app import scanner
from datetime import datetime, timedelta, timezone
from typing import Literal, AsyncGenerator

import bcrypt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, HttpUrl, field_validator
from sqlalchemy import text, Boolean, Column, DateTime, Integer, Numeric, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.future import select

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("purple-grid")

# ---------------------------------------------------------------------------
# Security config
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-openssl-rand-hex-32")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

bearer_scheme = HTTPBearer()

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://purplegrid:purplegrid@purple-grid-db:5432/purplegrid"
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ScanResultModel(Base):
    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    repo_url: Mapped[str] = mapped_column(String, nullable=False)
    branch: Mapped[str] = mapped_column(String, default="main")
    scan_depth: Mapped[str] = mapped_column(String, default="full")
    status: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Numeric(4, 2), nullable=True)
    total_vulns: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Purple-Grid Vulnerability Scanner API",
    description="AI-powered vulnerability analysis microservice.",
    version="3.0.0",
    docs_url="/docs" if os.getenv("ENV", "production") != "production" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("ENV", "production") != "production" else None,
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


@app.on_event("startup")
async def startup():
    # Verify DB connection on boot
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    logger.info("database_connected")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
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
    min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    repo_url: HttpUrl
    branch: str = "main"
    scan_depth: Literal["shallow", "full"] = "full"

    @field_validator("branch")
    @classmethod
    def branch_no_traversal(cls, v: str) -> str:
        if ".." in v or "/" in v:
            raise ValueError("Branch name must not contain path traversal sequences.")
        return v

class Vulnerability(BaseModel):
    finding_id: str          # was cve_id — static analysis finds CWEs, not CVEs
    engine: Literal["bandit", "semgrep"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cvss_score: float
    cwe: str | None = None
    file_path: str
    line_number: int
    title: str
    description: str

class ScanResult(BaseModel):
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


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> UserModel:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
    return user




# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )
    user = UserModel(
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()
    logger.info(f"user_registered email={payload.email}")
    return {"message": "Account created successfully."}


@app.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning(f"login_failed email={payload.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )
    token = create_access_token(subject=user.email)
    logger.info(f"login_success email={payload.email}")
    return TokenResponse(access_token=token, expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------
@app.post("/api/v1/scan", response_model=ScanResult, status_code=status.HTTP_200_OK)
async def scan_repository(
    payload: ScanRequest,
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())
    logger.info(f"scan_started scan_id={scan_id} user={current_user.email} repo={payload.repo_url}")

    try:
        scan = await scanner.run_scan(str(payload.repo_url), payload.branch, payload.scan_depth)
        SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

        all_findings = [Vulnerability(**v) for v in scan["vulnerabilities"]]
        duration_ms = scan["duration_ms"]

# Filter by min_severity then sort highest first
        findings = [
            f for f in all_findings
            if SEVERITY_RANK.get(f.severity, 0) >= SEVERITY_RANK[payload.min_severity]
        ]
        findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    except scanner.ScanError as exc:
        logger.warning(f"scan_rejected scan_id={scan_id} reason={exc}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error(f"scan_failed scan_id={scan_id} error={exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan engine encountered an internal error.")

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in findings:
        severity_counts[v.severity] += 1

    risk_score = round(sum(v.cvss_score for v in findings) / max(len(findings), 1), 2)
    scanned_at = datetime.now(timezone.utc)

    # Persist to DB
    db_scan = ScanResultModel(
        id=uuid.UUID(scan_id),
        user_id=current_user.id,
        repo_url=str(payload.repo_url),
        branch=payload.branch,
        scan_depth=payload.scan_depth,
        status="completed",
        risk_score=risk_score,
        total_vulns=len(findings),
        raw_payload={
            "summary": {"total_vulnerabilities": len(findings), "severity_breakdown": severity_counts, "risk_score": risk_score},
            "vulnerabilities": [v.model_dump() for v in findings],
        },
        created_at=scanned_at,
        completed_at=scanned_at,
    )
    db.add(db_scan)
    await db.flush()

    logger.info(f"scan_completed scan_id={scan_id} user={current_user.email} total={len(findings)}")

    return ScanResult(
        scan_id=scan_id,
        status="completed",
        repo_url=str(payload.repo_url),
        branch=payload.branch,
        scanned_at=scanned_at.isoformat(),
        duration_ms=duration_ms,
        summary={"total_vulnerabilities": len(findings), "severity_breakdown": severity_counts, "risk_score": risk_score},
        vulnerabilities=findings,
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResult)
async def get_scan(
    scan_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Validate the path param is a real UUID — reject garbage before hitting the DB.
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID format.")

    result = await db.execute(
        select(ScanResultModel).where(
            ScanResultModel.id == scan_uuid,
            ScanResultModel.user_id == current_user.id,   # IDOR protection: only your own scans
        )
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    payload = scan.raw_payload or {}
    return ScanResult(
        scan_id=str(scan.id),
        status=scan.status,
        repo_url=scan.repo_url,
        branch=scan.branch,
        scanned_at=scan.created_at.isoformat(),
        duration_ms=payload.get("duration_ms", 0),
        summary=payload.get("summary", {}),
        vulnerabilities=payload.get("vulnerabilities", []),
    )

# ---------------------------------------------------------------------------
# Health probes
# ---------------------------------------------------------------------------
@app.get("/healthz", include_in_schema=False)
async def liveness():
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
async def readiness():
    return {"status": "ready", "version": "3.0.0"}


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"unhandled_exception path={request.url.path} error={exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."},
    )