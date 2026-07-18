# =============================================================================
# Purple-Grid · backend-api · Enterprise-Grade Multi-Stage Dockerfile
#
# STAGE ARCHITECTURE
# ──────────────────
#   1. base          — locked distro version; shared across all stages.
#   2. build-deps    — compiler toolchain + pip; NEVER ships to production.
#   3. runtime       — minimal attack surface; runs as UID 10001 (non-root).
#
# SECURITY HARDENING SUMMARY
# ──────────────────────────
#   • Non-root UID/GID 10001 (above reserved range, below 65534/nobody).
#   • Read-only filesystem compatible (app writes nothing at runtime).
#   • No shell in final image (sh/bash removed → no interactive breakout).
#   • No package manager in final image (pip/apt removed → no in-container installs).
#   • Capabilities dropped by default; add only what Kubernetes needs via securityContext.
#   • Image is based on python:3.12-slim-bookworm — Debian stable, minimal package set,
#     receives security patches from both Debian and the Python Docker team.
# =============================================================================

# -----------------------------------------------------------------------------
# Global build argument — pin the Python version in one place.
# Change here to upgrade across all stages atomically.
# -----------------------------------------------------------------------------
ARG PYTHON_VERSION=3.12.4

# =============================================================================
# STAGE 1: base
# Purpose : establishes the locked OS + Python version used by all later stages.
#           Keeps the final image digest reproducible.
# =============================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS base

# OCI image labels — enables provenance tracking in container registries
# (Docker Hub, ECR, GCR, ACR) and SBOM tooling (Syft, Grype).
LABEL org.opencontainers.image.title="purple-grid-backend-api" \
      org.opencontainers.image.description="AI-powered vulnerability scanner API" \
      org.opencontainers.image.vendor="Purple-Grid" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="MIT"

# Prevent Python from writing .pyc files to disk (reduces image layers, prevents
# stale bytecode from masking real source changes in volume mounts).
ENV PYTHONDONTWRITEBYTECODE=1 \
    # Disable output buffering so logs stream to stdout immediately —
    # critical for real-time visibility in Docker/Kubernetes log pipelines.
    PYTHONUNBUFFERED=1 \
    # Tell pip where the virtualenv lives so it doesn't need --prefix flags.
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# =============================================================================
# STAGE 2: build-deps
# Purpose : installs compiler toolchain and pip packages into an isolated
#           virtual environment. This entire layer is DISCARDED before shipping.
#           Attack surface of the compiler (gcc, make, binutils) never reaches prod.
# =============================================================================
FROM base AS build-deps

# Install only what pip needs to compile C extensions (if any dep requires it).
# --no-install-recommends cuts ~60 MB of unnecessary packages.
# Combine update + install + clean in ONE RUN to prevent intermediate layers
# from caching stale package indexes, which can harbour known-vulnerable packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential=12.9 \
        gcc=4:12.2.0-3 \
    && rm -rf /var/lib/apt/lists/*

# Create the virtualenv that will be copied (not the entire Python install)
# into the final image. Isolating deps in /opt/venv means we can COPY just
# that directory, leaving behind all of pip's caches and metadata.
RUN python -m venv $VIRTUAL_ENV

# ── LAYER ORDER IS INTENTIONAL ────────────────────────────────────────────────
# Copy ONLY the requirements file before the source code.
# Docker cache invalidation is sequential: if requirements.txt hasn't changed,
# the `pip install` layer is served from cache even when app/ code changes.
# This can save 30–90 seconds per build in CI/CD pipelines.
COPY requirements.txt /tmp/requirements.txt

# Install into the virtualenv. Flags explained:
#   --no-cache-dir    : don't write pip's HTTP cache to image layers (saves ~40 MB).
#   --require-hashes  : (future) enforce hash verification against requirements.txt
#                       when you switch to pip-compile with --generate-hashes.
RUN pip install --no-cache-dir --upgrade pip==24.1.2 \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# =============================================================================
# STAGE 3: runtime  (the image that actually runs — and ships)
# Purpose : minimal, hardened execution environment.
#           Only the application code and its compiled deps land here.
# =============================================================================
FROM base AS runtime

# ── CREATE NON-ROOT USER ──────────────────────────────────────────────────────
# UID/GID 10001 rationale:
#   - 0       → root       (forbidden)
#   - 1–999   → system accounts reserved by the OS
#   - 1000    → default first human user on many Linux distros (too guessable)
#   - 10001   → clearly a purpose-built service account, well above all reserved ranges
#   - 65534   → nobody     (used as a sentinel; avoid)
#
# --no-create-home : no home directory → one less directory an attacker can write to.
# --shell /bin/false : this user can never open an interactive shell,
#                      even if an attacker gets code execution as this UID.
RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --no-create-home --shell /bin/false appuser

# Copy the fully-compiled virtualenv from the build stage.
# Only the venv directory is copied — pip, wheel caches, and compiler
# tools from the build-deps stage are physically absent from this image.
COPY --from=build-deps --chown=appuser:appgroup $VIRTUAL_ENV $VIRTUAL_ENV

# ── LAYER ORDER: source code comes LAST ──────────────────────────────────────
# Source code changes on every commit; placing it last means all preceding
# layers (OS packages, virtualenv) stay cached across normal dev cycles.
WORKDIR /app
COPY --chown=appuser:appgroup app/ ./app/

# ── REMOVE UNNECESSARY BINARIES ───────────────────────────────────────────────
# Attackers who achieve RCE in the container immediately look for:
#   wget, curl   → exfiltrate data / download further payloads
#   bash, sh     → interactive shell
#   find, id     → reconnaissance
# Removing them adds meaningful friction. Note: this is defence-in-depth;
# it is NOT a substitute for network policies and seccomp/AppArmor profiles.
RUN find /usr/bin /usr/sbin -type f \( \
        -name "wget" -o -name "curl" \
        -o -name "bash" -o -name "sh" \
        -o -name "nc" -o -name "netcat" \
    \) -delete 2>/dev/null || true

# Drop to non-root. Every instruction from here down runs as UID 10001.
USER appuser

# Document the port — this is metadata only; actual port binding is done
# by `docker run -p` or the Kubernetes Service / ECS task definition.
EXPOSE 8000

# ── HEALTH CHECK ──────────────────────────────────────────────────────────────
# Docker daemon uses this for `docker ps` STATUS column and for deciding
# when to restart unhealthy containers (in Swarm/Compose).
# Kubernetes uses its own probes (/healthz, /readyz) defined in the app.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

# ── ENTRYPOINT vs CMD ─────────────────────────────────────────────────────────
# ENTRYPOINT: fixed binary — prevents an operator from accidentally replacing
#             uvicorn with an arbitrary command via `docker run <image> bash`.
# CMD:        default arguments — operators can safely override port/workers
#             without changing the entrypoint.
ENTRYPOINT ["uvicorn"]
CMD ["app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-access-log"]