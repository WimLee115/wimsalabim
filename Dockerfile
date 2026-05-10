# syntax=docker/dockerfile:1.7
#
# wimsalabim — multi-stage container build
# Final image: ~75 MB on python:3.12-slim, runs as non-root user 'wimsalabim'.
# Usage:
#     docker build -t wimsalabim .
#     docker run --rm wimsalabim scan example.com
#

# ─── Stage 1 · build wheel ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install .

# ─── Stage 2 · runtime ──────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="wimsalabim" \
      org.opencontainers.image.description="Honest, audit-grade website security and privacy reconnaissance" \
      org.opencontainers.image.source="https://github.com/WimLee115/wimsalabim" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.authors="Captain WimLee115" \
      org.opencontainers.image.vendor="PVNL · Privacy Verzet NL"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Non-root user with deterministic uid/gid for volume permissions.
RUN groupadd --gid 1000 wimsalabim && \
    useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin wimsalabim

COPY --from=builder /opt/venv /opt/venv

USER wimsalabim
WORKDIR /home/wimsalabim

# Reports/keys directory pre-mountable as a volume.
VOLUME ["/home/wimsalabim/.wimsalabim"]

ENTRYPOINT ["wimsalabim"]
CMD ["--help"]

# Healthcheck — confirm the binary still resolves.
HEALTHCHECK --interval=30s --timeout=5s --start-period=2s --retries=2 \
    CMD ["/opt/venv/bin/wimsalabim", "--version"]
