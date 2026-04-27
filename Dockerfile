# syntax=docker/dockerfile:1
# Eagle Eyed Dom — DHI hardened multi-stage production image
#
# Build:  podman build --platform linux/arm64 -t eedom:latest .
# Test:   EEDOM_IMAGE=eedom:latest uv run pytest tests/integration/test_dockerfile.py -v

# ── Version pins ─────────────────────────────────────────────────────────────
ARG SYFT_VERSION=1.21.0
ARG TRIVY_VERSION=0.70.0
ARG OSV_VERSION=2.0.1
ARG OPA_VERSION=1.4.2
ARG GITLEAKS_VERSION=8.24.3
ARG JQ_VERSION=1.7.1
ARG KUBE_LINTER_VERSION=0.8.3
ARG SEMGREP_VERSION=1.67.0
ARG SCANCODE_VERSION=32.3.0
ARG PMD_VERSION=7.24.0
ARG LIZARD_VERSION=1.17.13
ARG MYPY_VERSION=1.15.0
ARG CSPELL_VERSION=8.18.1

# ── SHA256 checksums — per architecture ──────────────────────────────────────
# Build fails hard if any hash mismatches — no silent pass.
# PMD is architecture-independent (Java).
ARG SYFT_SHA256_ARM64=b7617868459cb707e4f9f56c8cb121124bf90b2c944f30e2f3c773807e1e05d7
ARG TRIVY_SHA256_ARM64=2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d
ARG OSV_SHA256_ARM64=9ce9c96e3ae4526f8e077e6b456bc82bb2070abd5bbfac966a8dbbbb93a50fd2
ARG OPA_SHA256_ARM64=facd6a9ea375c6299701f86b90b470e52305c5726c4f136e2980fa6123ae9613
ARG GITLEAKS_SHA256_ARM64=5f2edbe1f49f7b920f9e06e90759947d3c5dfc16f752fb93aaafc17e9d14cf07
ARG JQ_SHA256_ARM64=4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5
ARG KUBE_LINTER_SHA256_ARM64=802e1b09eabd08f6f0a060a6b8ab2bf7bc7e6bf4f673bb2692303704c84b3e22
ARG PMD_SHA256=110934b36d39c19094d1b77386931978093f238f2c2f1851748822b69c7367ac

# AMD64 checksums — populate when adding amd64 support
ARG SYFT_SHA256_AMD64=PLACEHOLDER
ARG TRIVY_SHA256_AMD64=PLACEHOLDER
ARG OSV_SHA256_AMD64=PLACEHOLDER
ARG OPA_SHA256_AMD64=PLACEHOLDER
ARG GITLEAKS_SHA256_AMD64=PLACEHOLDER
ARG JQ_SHA256_AMD64=PLACEHOLDER
ARG KUBE_LINTER_SHA256_AMD64=PLACEHOLDER

# ════════════════════════════════════════════════════════════════════════════
# Stage 1: builder
# ════════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim-bookworm AS builder

ARG SYFT_VERSION TRIVY_VERSION OSV_VERSION OPA_VERSION GITLEAKS_VERSION JQ_VERSION KUBE_LINTER_VERSION PMD_VERSION
ARG SYFT_SHA256_ARM64 TRIVY_SHA256_ARM64 OSV_SHA256_ARM64 OPA_SHA256_ARM64 GITLEAKS_SHA256_ARM64 JQ_SHA256_ARM64 KUBE_LINTER_SHA256_ARM64 PMD_SHA256
ARG SYFT_SHA256_AMD64 TRIVY_SHA256_AMD64 OSV_SHA256_AMD64 OPA_SHA256_AMD64 GITLEAKS_SHA256_AMD64 JQ_SHA256_AMD64 KUBE_LINTER_SHA256_AMD64
ARG SEMGREP_VERSION SCANCODE_VERSION LIZARD_VERSION MYPY_VERSION CSPELL_VERSION
ARG TARGETARCH

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip pkg-config libicu-dev gcc g++ python3-dev

RUN mkdir -p /staging/gobin /staging/jq /staging/pmd /staging/scripts

# ── All Go/native binaries — single layer, arch-aware ────────────────────────
RUN set -eux; \
    case "${TARGETARCH}" in \
        "amd64") \
            SYFT_ARCH="amd64";       SYFT_SHA="${SYFT_SHA256_AMD64}"; \
            TRIVY_ARCH="64bit";      TRIVY_SHA="${TRIVY_SHA256_AMD64}"; \
            OSV_ARCH="amd64";        OSV_SHA="${OSV_SHA256_AMD64}"; \
            OPA_ARCH="amd64_static"; OPA_SHA="${OPA_SHA256_AMD64}"; \
            GITLEAKS_ARCH="x64";     GITLEAKS_SHA="${GITLEAKS_SHA256_AMD64}"; \
            JQ_ARCH="amd64";         JQ_SHA="${JQ_SHA256_AMD64}"; \
            KL_ARCH="amd64";         KL_SHA="${KUBE_LINTER_SHA256_AMD64}" ;; \
        "arm64") \
            SYFT_ARCH="arm64";       SYFT_SHA="${SYFT_SHA256_ARM64}"; \
            TRIVY_ARCH="ARM64";      TRIVY_SHA="${TRIVY_SHA256_ARM64}"; \
            OSV_ARCH="arm64";        OSV_SHA="${OSV_SHA256_ARM64}"; \
            OPA_ARCH="arm64_static"; OPA_SHA="${OPA_SHA256_ARM64}"; \
            GITLEAKS_ARCH="arm64";   GITLEAKS_SHA="${GITLEAKS_SHA256_ARM64}"; \
            JQ_ARCH="arm64";         JQ_SHA="${JQ_SHA256_ARM64}"; \
            KL_ARCH="arm64";         KL_SHA="${KUBE_LINTER_SHA256_ARM64}" ;; \
        *) echo "Fatal: unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz"; \
    echo "${SYFT_SHA}  /tmp/syft.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/syft.tar.gz -C /staging/gobin syft; \
    curl -sSfL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
    echo "${TRIVY_SHA}  /tmp/trivy.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /staging/gobin trivy; \
    curl -sSfL -o /staging/gobin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV_ARCH}"; \
    echo "${OSV_SHA}  /staging/gobin/osv-scanner" | sha256sum --strict -c -; \
    curl -sSfL -o /staging/gobin/opa "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${OPA_ARCH}"; \
    echo "${OPA_SHA}  /staging/gobin/opa" | sha256sum --strict -c -; \
    curl -sSfL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA}  /tmp/gitleaks.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /staging/gobin gitleaks; \
    curl -sSfL -o /tmp/kube-linter.tar.gz "https://github.com/stackrox/kube-linter/releases/download/v${KUBE_LINTER_VERSION}/kube-linter-linux_${KL_ARCH}.tar.gz"; \
    echo "${KL_SHA}  /tmp/kube-linter.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/kube-linter.tar.gz -C /staging/gobin kube-linter; \
    curl -sSfL -o /tmp/pmd.zip "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VERSION}/pmd-dist-${PMD_VERSION}-bin.zip"; \
    echo "${PMD_SHA256}  /tmp/pmd.zip" | sha256sum --strict -c -; \
    unzip -q /tmp/pmd.zip -d /staging/pmd; \
    curl -sSfL -o /staging/jq/jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${JQ_ARCH}"; \
    echo "${JQ_SHA}  /staging/jq/jq" | sha256sum --strict -c -; \
    rm -f /tmp/*.tar.gz /tmp/*.zip; \
    chmod +x /staging/gobin/* /staging/jq/jq

# ── Build-time checksums for runtime verification ────────────────────────────
RUN for b in syft trivy osv-scanner opa gitleaks kube-linter; do \
      sha256sum "/staging/gobin/$b" | sed "s|/staging/gobin/$b|/usr/local/bin/$b|"; \
    done > /staging/scripts/checksums.txt \
    && sha256sum /staging/jq/jq | sed 's|/staging/jq/jq|/usr/bin/jq|' >> /staging/scripts/checksums.txt

# ── Python packages ──────────────────────────────────────────────────────────
# pip --target isolates from system Python. Deps first (cached), source last.
#
# TODO(#115): Replace inline pins with `pip install --require-hashes -r requirements.lock`
#             generated via `uv pip compile --generate-hashes`. Delete the inline block below.
WORKDIR /opt/eedom

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --target=/opt/pysite \
      click==8.3.3 "pydantic==2.13.3" "pydantic-settings==2.14.0" "structlog==25.5.0" \
      "httpx==0.28.1" "psycopg[binary]==3.3.3" "psycopg-pool==3.3.0" "orjson==3.11.8" \
      "packaging==26.1" "pyarrow==24.0.0" "agent-framework-github-copilot==1.0.0b260423" \
      "jinja2==3.1.6" "pyyaml==6.0.3" "watchdog==6.0.0" "rich>=13.7.0" \
      "semgrep==${SEMGREP_VERSION}" "scancode-toolkit==${SCANCODE_VERSION}" \
      "lizard==${LIZARD_VERSION}" "mypy==${MYPY_VERSION}"

COPY pyproject.toml LICENSE README.md ./
COPY src/ src/
COPY policies/ policies/
COPY migrations/ migrations/

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --target=/opt/pysite .

# ── Module entry point fixes ────────────────────────────────────────���────────
# pip --target does not create console_scripts. Plugin runners call bare tool
# names, so we need `python3 -m <module>` to work. These overrides are needed
# until we switch to a real venv (#117) which creates proper entry points.

# Semgrep ≥1.38 __main__.py deliberately exits 2 with a deprecation notice.
RUN printf '%s\n' \
      'from semgrep.cli import cli' \
      'if __name__ == "__main__":' \
      '    cli()' \
    > /opt/pysite/semgrep/__main__.py

# scancode-toolkit ships no __main__.py. Short-circuit --version to avoid
# the full plugin load which triggers ctypes/libarchive imports.
RUN printf '%s\n' \
      'import sys' \
      'if len(sys.argv) >= 2 and sys.argv[1] == "--version":' \
      '    try:' \
      '        from importlib.metadata import version as _v' \
      '        print("ScanCode version " + _v("scancode-toolkit"))' \
      '    except Exception:' \
      '        print("ScanCode version unavailable")' \
      '    sys.exit(0)' \
      'from scancode.cli import scancode' \
      'if __name__ == "__main__":' \
      '    scancode()' \
    > /opt/pysite/scancode/__main__.py

# ════════════════════════════════════════════════════════════════════════════
# Stage 2: runtime
# ════════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim-bookworm

ARG CSPELL_VERSION
ARG PMD_VERSION

LABEL org.opencontainers.image.title="Eagle Eyed Dom" \
      org.opencontainers.image.description="DHI hardened multi-stage production scanner" \
      org.opencontainers.image.source="https://github.com/gitrdunhq/eedom"

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      git clamav clamav-freshclam libicu72 libarchive13 ca-certificates \
      default-jre-headless nodejs npm \
    && npm install -g "cspell@${CSPELL_VERSION}" --no-fund --no-audit \
    && npm cache clean --force \
    && apt-get purge -y npm \
    && apt-get autoremove -y

# Non-root user — scanners must not run as root.
RUN groupadd -r eedom && useradd -r -g eedom -m -d /home/eedom -s /bin/false eedom

# ClamAV directories — present but empty. Signatures are fetched at scan time
# via `freshclam --quiet` in the CI workflow, never baked into the image.
RUN mkdir -p /var/lib/clamav /var/log/clamav \
    && chown -R eedom:eedom /var/lib/clamav /var/log/clamav \
    && chmod 0750 /var/lib/clamav /var/log/clamav

# ── Staged artifacts from builder ────────────────────────────────────────────
COPY --from=builder /staging/gobin/syft        /usr/local/bin/syft
COPY --from=builder /staging/gobin/trivy       /usr/local/bin/trivy
COPY --from=builder /staging/gobin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /staging/gobin/opa         /usr/local/bin/opa
COPY --from=builder /staging/gobin/gitleaks    /usr/local/bin/gitleaks
COPY --from=builder /staging/gobin/kube-linter /usr/local/bin/kube-linter
COPY --from=builder /staging/pmd/              /opt/pmd/
COPY --from=builder /staging/jq/jq             /usr/bin/jq
COPY --from=builder /opt/pysite/               /opt/pysite/

# Jinja2 templates — not picked up by pip --target (see #118)
COPY src/eedom/templates/ /opt/pysite/eedom/templates/

COPY --from=builder /opt/eedom/policies/ /opt/eedom/policies/

RUN mkdir -p /opt/eedom/scripts
COPY --from=builder /staging/scripts/checksums.txt /opt/eedom/scripts/checksums.txt
COPY scripts/verify-checksums.sh /opt/eedom/scripts/verify-checksums.sh
RUN chmod +x /opt/eedom/scripts/verify-checksums.sh

# ── CLI wrappers ─────────────────────────────────────────────────────────────
# pip --target does not generate console_scripts. Shell wrappers bridge the gap.
# TODO(#117): Replace with venv approach that creates proper entry points.
RUN printf '#!/bin/sh\nexec python3 -m eedom.cli.main "$@"\n' > /usr/local/bin/eedom \
    && chmod +x /usr/local/bin/eedom \
    && for tool in semgrep scancode lizard mypy; do \
         printf '#!/bin/sh\nexec python3 -m %s "$@"\n' "$tool" > "/usr/local/bin/$tool" \
         && chmod +x "/usr/local/bin/$tool"; \
       done \
    && printf '#!/bin/sh\nexec /opt/pmd/pmd-bin-%s/bin/pmd "$@"\n' "${PMD_VERSION}" > /usr/local/bin/pmd \
    && chmod +x /usr/local/bin/pmd

# Entrypoint verifies binary integrity before running eedom
RUN printf '#!/bin/sh\n/opt/eedom/scripts/verify-checksums.sh || exit 1\nexec eedom "$@"\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh

ENV PYTHONPATH=/opt/pysite \
    TRIVY_CACHE_DIR=/home/eedom/.cache/trivy \
    MYPY_CACHE_DIR=/home/eedom/.cache/mypy \
    SEMGREP_USER_DATA_FOLDER=/home/eedom/.cache/semgrep \
    XDG_CACHE_HOME=/home/eedom/.cache \
    EEDOM_OPERATING_MODE=monitor \
    EEDOM_OPA_POLICY_PATH=/opt/eedom/policies \
    EEDOM_ENABLED_SCANNERS=syft,osv-scanner,trivy,scancode,semgrep,gitleaks,clamav,kube-linter,pmd,lizard,mypy,cspell

USER eedom
WORKDIR /home/eedom

HEALTHCHECK --interval=5m --timeout=30s --retries=3 \
  CMD eedom healthcheck || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
