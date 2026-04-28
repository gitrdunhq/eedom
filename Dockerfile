# syntax=docker/dockerfile:1
# Eagle Eyed Dom — DHI hardened multi-stage production image
#
# Build:  podman build --platform linux/arm64 -t eedom:latest .
# Test:   EEDOM_IMAGE=eedom:latest uv run pytest tests/integration/test_dockerfile.py -v

# ── Version pins ─────────────────────────────────────────────────────────────
ARG SYFT_VERSION=1.43.0
ARG TRIVY_VERSION=0.70.0
ARG OSV_VERSION=2.3.5
ARG OPA_VERSION=1.15.2
ARG GITLEAKS_VERSION=8.30.1
ARG JQ_VERSION=1.7.1
ARG KUBE_LINTER_VERSION=0.8.3
ARG SEMGREP_VERSION=1.67.0
ARG SCANCODE_VERSION=32.3.0
ARG LIZARD_VERSION=1.17.13
ARG MYPY_VERSION=1.15.0
ARG CSPELL_VERSION=8.18.1
ARG LS_LINT_VERSION=2.3.1
ARG PMD_VERSION=7.24.0

# ── SHA256 checksums — per architecture ──────────────────────────────────────
# Build fails hard if any hash mismatches — no silent pass.
# PMD is architecture-independent (Java).
ARG SYFT_SHA256_ARM64=afe92510c467f952a009b994f2d998ff8f9dd266dc26eca55d14a0dd46fec7f2
ARG TRIVY_SHA256_ARM64=2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d
ARG OSV_SHA256_ARM64=fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50
ARG OPA_SHA256_ARM64=6651bf5a80cfec6ba6a2d3b6a550b8f748d9cade1c74d54b5f854782f9bea67a
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG JQ_SHA256_ARM64=4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5
ARG KUBE_LINTER_SHA256_ARM64=802e1b09eabd08f6f0a060a6b8ab2bf7bc7e6bf4f673bb2692303704c84b3e22
ARG LS_LINT_SHA256_ARM64=2abdb71243c619f0bb29587be5c228bec84c107985f2c066139ef0ec35fd3a99
ARG PMD_SHA256=110934b36d39c19094d1b77386931978093f238f2c2f1851748822b69c7367ac

ARG SYFT_SHA256_AMD64=7b98251d2d08926bb5d4639b56b1f0996a58ef6667c5830e3fe3cd3ad5f4214a
ARG TRIVY_SHA256_AMD64=8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9
ARG OSV_SHA256_AMD64=bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b
ARG OPA_SHA256_AMD64=a9d9481e463e7af8cb1a2cd7c3deb764f0327b3281c54e632546c2f425fc0824
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG JQ_SHA256_AMD64=5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5
ARG KUBE_LINTER_SHA256_AMD64=1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df
ARG LS_LINT_SHA256_AMD64=b5a0d2e4427ad039fbc574551f17679f38f142b25d15e0e538769f8cf15af397

# ════════════════════════════════════════════════════════════════════════════
# Stage 1: builder
# ════════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim-trixie AS builder

ARG SYFT_VERSION TRIVY_VERSION OSV_VERSION OPA_VERSION GITLEAKS_VERSION JQ_VERSION KUBE_LINTER_VERSION PMD_VERSION LS_LINT_VERSION
ARG SEMGREP_VERSION SCANCODE_VERSION LIZARD_VERSION MYPY_VERSION
ARG SYFT_SHA256_ARM64 TRIVY_SHA256_ARM64 OSV_SHA256_ARM64 OPA_SHA256_ARM64 GITLEAKS_SHA256_ARM64 JQ_SHA256_ARM64 KUBE_LINTER_SHA256_ARM64 LS_LINT_SHA256_ARM64 PMD_SHA256
ARG SYFT_SHA256_AMD64 TRIVY_SHA256_AMD64 OSV_SHA256_AMD64 OPA_SHA256_AMD64 GITLEAKS_SHA256_AMD64 JQ_SHA256_AMD64 KUBE_LINTER_SHA256_AMD64 LS_LINT_SHA256_AMD64
ARG TARGETARCH

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip pkg-config libicu-dev gcc g++ python3-dev

RUN mkdir -p /staging/gobin /staging/jq /staging/pmd /staging/scripts

# ── All Go/native binaries — single layer, arch-aware ────────────────────────
# kube-linter uses no arch suffix for amd64, _arm64 suffix for arm64.
RUN set -eux; \
    case "${TARGETARCH}" in \
        "amd64") \
            SYFT_ARCH="amd64";       SYFT_SHA="${SYFT_SHA256_AMD64}"; \
            TRIVY_ARCH="64bit";      TRIVY_SHA="${TRIVY_SHA256_AMD64}"; \
            OSV_ARCH="amd64";        OSV_SHA="${OSV_SHA256_AMD64}"; \
            OPA_ARCH="amd64_static"; OPA_SHA="${OPA_SHA256_AMD64}"; \
            GITLEAKS_ARCH="x64";     GITLEAKS_SHA="${GITLEAKS_SHA256_AMD64}"; \
            JQ_ARCH="amd64";         JQ_SHA="${JQ_SHA256_AMD64}"; \
            KL_SUFFIX="";           KL_SHA="${KUBE_LINTER_SHA256_AMD64}"; \
            LL_ARCH="amd64";         LL_SHA="${LS_LINT_SHA256_AMD64}" ;; \
        "arm64") \
            SYFT_ARCH="arm64";       SYFT_SHA="${SYFT_SHA256_ARM64}"; \
            TRIVY_ARCH="ARM64";      TRIVY_SHA="${TRIVY_SHA256_ARM64}"; \
            OSV_ARCH="arm64";        OSV_SHA="${OSV_SHA256_ARM64}"; \
            OPA_ARCH="arm64_static"; OPA_SHA="${OPA_SHA256_ARM64}"; \
            GITLEAKS_ARCH="arm64";   GITLEAKS_SHA="${GITLEAKS_SHA256_ARM64}"; \
            JQ_ARCH="arm64";         JQ_SHA="${JQ_SHA256_ARM64}"; \
            KL_SUFFIX="_arm64";     KL_SHA="${KUBE_LINTER_SHA256_ARM64}"; \
            LL_ARCH="arm64";         LL_SHA="${LS_LINT_SHA256_ARM64}" ;; \
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
    curl -sSfL -o /tmp/kube-linter.tar.gz "https://github.com/stackrox/kube-linter/releases/download/v${KUBE_LINTER_VERSION}/kube-linter-linux${KL_SUFFIX}.tar.gz"; \
    echo "${KL_SHA}  /tmp/kube-linter.tar.gz" | sha256sum --strict -c -; \
    tar -xzf /tmp/kube-linter.tar.gz -C /staging/gobin kube-linter; \
    curl -sSfL -o /staging/gobin/ls-lint "https://github.com/loeffel-io/ls-lint/releases/download/v${LS_LINT_VERSION}/ls-lint-linux-${LL_ARCH}"; \
    echo "${LL_SHA}  /staging/gobin/ls-lint" | sha256sum --strict -c -; \
    curl -sSfL -o /tmp/pmd.zip "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VERSION}/pmd-dist-${PMD_VERSION}-bin.zip"; \
    echo "${PMD_SHA256}  /tmp/pmd.zip" | sha256sum --strict -c -; \
    unzip -q /tmp/pmd.zip -d /staging/pmd; \
    curl -sSfL -o /staging/jq/jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${JQ_ARCH}"; \
    echo "${JQ_SHA}  /staging/jq/jq" | sha256sum --strict -c -; \
    rm -f /tmp/*.tar.gz /tmp/*.zip; \
    chmod +x /staging/gobin/* /staging/jq/jq

# ── Build-time checksums for runtime verification ────────────────────────────
RUN for b in syft trivy osv-scanner opa gitleaks kube-linter ls-lint; do \
      sha256sum "/staging/gobin/$b" | sed "s|/staging/gobin/$b|/usr/local/bin/$b|"; \
    done > /staging/scripts/checksums.txt \
    && sha256sum /staging/jq/jq | sed 's|/staging/jq/jq|/usr/bin/jq|' >> /staging/scripts/checksums.txt

# ── Python: lockfile-based venv install ──────────────────────────────────────
RUN pip install --no-cache-dir uv
WORKDIR /opt/eedom

COPY pyproject.toml uv.lock LICENSE README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra all --no-editable --no-install-project

COPY src/ src/
COPY policies/ policies/
COPY migrations/ migrations/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra all --no-editable

# Scanner tools — external CLIs installed into the same venv, version-pinned by ARG.
# Not in the lockfile because scancode-toolkit's transitive dep (extractcode-7z)
# lacks arm64 wheels, breaking cross-platform uv sync.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install \
      "semgrep==${SEMGREP_VERSION}" \
      "scancode-toolkit==${SCANCODE_VERSION}" \
      "lizard==${LIZARD_VERSION}" \
      "mypy==${MYPY_VERSION}"

# scancode's plugin loader crashes on arm64 (extractcode-libarchive has no arm64 wheel).
# Replace the console_script with a wrapper that defers the import.
RUN printf '%s\n' \
      '#!/opt/eedom/.venv/bin/python3' \
      'import sys' \
      'if "--version" in sys.argv:' \
      '    from importlib.metadata import version' \
      '    print("ScanCode version", version("scancode-toolkit"))' \
      '    sys.exit(0)' \
      'from scancode.cli import scancode' \
      'scancode()' \
    > /opt/eedom/.venv/bin/scancode \
    && chmod +x /opt/eedom/.venv/bin/scancode

# ════════════════════════════════════════════════════════════════════════════
# Stage 2: runtime
# ════════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim-trixie

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
      git clamav clamav-freshclam libicu76 libarchive13t64 ca-certificates curl gnupg \
      default-jre-headless ruby ruby-dev build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g "cspell@${CSPELL_VERSION}" "aws-cdk" --no-fund --no-audit \
    && npm cache clean --force \
    && gem install cfn-nag --no-document \
    && apt-get purge -y build-essential ruby-dev curl gnupg \
    && apt-get autoremove -y

# Non-root user — scanners must not run as root.
RUN groupadd -r eedom && useradd -r -g eedom -m -d /home/eedom -s /bin/false eedom \
    && mkdir -p /var/lib/clamav /var/log/clamav \
    && chown -R eedom:eedom /var/lib/clamav /var/log/clamav \
    && chmod 0750 /var/lib/clamav /var/log/clamav

# ── Staged artifacts from builder ────────────────────────────────────────────
COPY --from=builder /staging/gobin/syft        /usr/local/bin/syft
COPY --from=builder /staging/gobin/trivy       /usr/local/bin/trivy
COPY --from=builder /staging/gobin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /staging/gobin/opa         /usr/local/bin/opa
COPY --from=builder /staging/gobin/gitleaks    /usr/local/bin/gitleaks
COPY --from=builder /staging/gobin/kube-linter /usr/local/bin/kube-linter
COPY --from=builder /staging/gobin/ls-lint    /usr/local/bin/ls-lint
COPY --from=builder /staging/pmd/              /opt/pmd/
COPY --from=builder /staging/jq/jq             /usr/bin/jq

# Venv with all Python deps + eedom itself — console_scripts are in .venv/bin/
COPY --from=builder /opt/eedom/.venv /opt/eedom/.venv
COPY --from=builder /opt/eedom/policies/ /opt/eedom/policies/

RUN mkdir -p /opt/eedom/scripts
COPY --from=builder /staging/scripts/checksums.txt /opt/eedom/scripts/checksums.txt
COPY scripts/verify-checksums.sh /opt/eedom/scripts/verify-checksums.sh
RUN chmod +x /opt/eedom/scripts/verify-checksums.sh

# PMD wrapper — Java-based, not in the venv
RUN printf '#!/bin/sh\nexec /opt/pmd/pmd-bin-%s/bin/pmd "$@"\n' "${PMD_VERSION}" > /usr/local/bin/pmd \
    && chmod +x /usr/local/bin/pmd

# Entrypoint verifies binary integrity before running eedom
RUN printf '#!/bin/sh\n/opt/eedom/scripts/verify-checksums.sh || exit 1\nexec eedom "$@"\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh

ENV PATH="/opt/eedom/.venv/bin:$PATH" \
    VIRTUAL_ENV="/opt/eedom/.venv" \
    TRIVY_CACHE_DIR=/home/eedom/.cache/trivy \
    MYPY_CACHE_DIR=/home/eedom/.cache/mypy \
    SEMGREP_USER_DATA_FOLDER=/home/eedom/.cache/semgrep \
    XDG_CACHE_HOME=/home/eedom/.cache \
    EEDOM_OPERATING_MODE=monitor \
    EEDOM_OPA_POLICY_PATH=/opt/eedom/policies \
    EEDOM_ENABLED_SCANNERS=syft,osv-scanner,trivy,scancode,semgrep,gitleaks,clamav,kube-linter,pmd,lizard,mypy,cspell,ls-lint,cdk-nag,cfn-nag

USER eedom
WORKDIR /home/eedom

HEALTHCHECK --interval=5m --timeout=30s --retries=3 \
  CMD eedom healthcheck || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
