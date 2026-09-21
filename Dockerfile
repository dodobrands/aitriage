# ─── Stage 1: Build Web UI ───────────────────────────────────────────────────
FROM node:22-bookworm AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ─── Stage 2: Build Go binary ─────────────────────────────────────────────────
FROM golang:1.25.13-bookworm AS go-builder
WORKDIR /app

# C deps for tree-sitter CGO
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Synchronize web assets into the Go binary build context
COPY --from=web-builder /web/dist /app/internal/server/ui/dist
ARG AITRIAGE_VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags="-s -w -X main.Version=${AITRIAGE_VERSION}" -o /aitriage ./cmd/aitriage

# Build the latest upstream Gitleaks release with patched Go dependencies. The
# upstream v8.30.1 asset was built with Go 1.24.11 and x/crypto 0.35.0, both of
# which now have fixable HIGH CVEs. Module source is authenticated by Go sumdb.
FROM --platform=$BUILDPLATFORM golang:1.25.13-bookworm AS gitleaks-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN go mod download github.com/zricethezav/gitleaks/v8@v8.30.1 && \
    cp -a /go/pkg/mod/github.com/zricethezav/gitleaks/v8@v8.30.1/. /src/ && \
    chmod -R u+w /src && \
    go mod edit -require=golang.org/x/crypto@v0.55.0 && \
    go mod edit -require=golang.org/x/text@v0.39.0 && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -trimpath -ldflags="-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=v8.30.1" -o /gitleaks .

# Trivy v0.72.0 was released with Go 1.26.4 and oras-go 2.6.0. Rebuilding the
# exact tagged source on a patched toolchain and patched dependencies removes the
# fixable CVEs without changing Trivy's scanner version or behavior.
#
# Every pin below answers a CVE the image gate reported, and each one has to be
# revisited whenever a new advisory lands — this is the same maintenance that
# blocked v1.11.1. Current set: Go 1.26.6 (stdlib), x/crypto 0.55.0,
# x/net 0.56.0, x/mod 0.40.0, gRPC-Go 1.83.2.
FROM --platform=$BUILDPLATFORM golang:1.26.6-bookworm AS trivy-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN go mod download github.com/aquasecurity/trivy@v0.72.0 && \
    cp -a /go/pkg/mod/github.com/aquasecurity/trivy@v0.72.0/. /src/ && \
    chmod -R u+w /src && \
    go mod edit -require=oras.land/oras-go/v2@v2.6.2 && \
    go mod edit -require=github.com/go-git/go-git/v5@v5.19.2 && \
    go mod edit -require=golang.org/x/text@v0.39.0 && \
    go mod edit -require=golang.org/x/crypto@v0.55.0 && \
    go mod edit -require=golang.org/x/net@v0.56.0 && \
    go mod edit -require=golang.org/x/mod@v0.40.0 && \
    go mod edit -require=google.golang.org/grpc@v1.83.2 && \
    go mod tidy && \
    GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -trimpath -ldflags="-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=0.72.0" -o /trivy ./cmd/trivy

# ─── Stage 3: Runtime with all security tools ─────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="AITriage"
LABEL org.opencontainers.image.description="AI-powered security scanner — all tools included"
LABEL org.opencontainers.image.source="https://github.com/dodobrands/aitriage"

# System deps + runtime C libs (merged into single layer for cache)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 python3-pip python3-venv \
    libgcc-s1 libc6 \
    && rm -rf /var/lib/apt/lists/*

# ── semgrep + bandit via pipx (pipx is build-time only) ──────────────────────
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
# Semgrep 1.170.1 pins mcp 1.23.3 (three fixable HIGH CVEs); upstream 1.172.0
# still pins it, so this patched override is deliberate and E2E-proven.
# AITriage never exposes Semgrep's MCP server.
#
# pip vendors its own msgpack/setuptools versions inside pip/_vendor/vendor.txt.
# They are not installed distributions and cannot be patched with pip install.
# Remove the complete pip/pipx toolchain after provisioning the scanner venvs.
RUN pip3 install --break-system-packages --no-cache-dir 'pipx==1.8.0' && \
    pipx install 'semgrep==1.170.1' && \
    pipx runpip semgrep install --no-cache-dir 'mcp==1.28.1' 'setuptools==83.0.0' && \
    pipx install 'bandit==1.9.4' && \
    pipx runpip bandit install --no-cache-dir 'setuptools==83.0.0' && \
    semgrep --version && semgrep scan --help >/dev/null && \
    /opt/pipx/venvs/semgrep/bin/python -c \
      "import importlib.metadata as m; assert m.version('mcp') == '1.28.1'; assert m.version('setuptools') == '83.0.0'" && \
    /opt/pipx/venvs/bandit/bin/python -c \
      "import importlib.metadata as m; assert m.version('setuptools') == '83.0.0'" && \
    bandit --version && \
    rm -rf /opt/pipx/shared /opt/pipx/.cache && \
    rm -rf /opt/pipx/venvs/*/lib/python*/site-packages/pip \
           /opt/pipx/venvs/*/lib/python*/site-packages/pip-*.dist-info \
           /opt/pipx/venvs/*/lib/python*/site-packages/pipx_shared.pth \
           /opt/pipx/venvs/*/bin/pip* && \
    pip3 uninstall --break-system-packages -y pipx && \
    rm -rf /root/.cache /root/.local && \
    semgrep --version && semgrep scan --help >/dev/null && bandit --version

# ── Patched source-built external scanners ───────────────────────────────────
COPY --from=gitleaks-builder /gitleaks /usr/local/bin/gitleaks
COPY --from=trivy-builder /trivy /usr/local/bin/trivy

# Build-only Python packaging tools are not needed at runtime. Removing the
# distro setuptools metadata also removes two fixable CVEs from the final image.
RUN apt-get purge -y \
      python3-setuptools python3-pip python3-venv python3.11-venv \
      python3-pip-whl python3-setuptools-whl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /root/.cache && \
    test -z "$(find / -xdev -path '*/pip/_vendor*' -print -quit)" && \
    test -z "$(find / -xdev -name 'pip-*.dist-info' -print -quit)" && \
    ! command -v pip3 >/dev/null && \
    ! command -v pipx >/dev/null && \
    semgrep --version && semgrep scan --help >/dev/null && bandit --version

# GitHub Action entrypoint wrapper (referenced by action.yml via `entrypoint:`)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── AITriage binary (LAST — changes every build, everything above is cached) ─
ARG AITRIAGE_VERSION=dev
ENV AITRIAGE_VERSION=${AITRIAGE_VERSION}
COPY --from=go-builder /aitriage /usr/local/bin/aitriage

# Create non-root user
RUN groupadd -g 1000 aitriage && \
    useradd -u 1000 -g aitriage -s /bin/bash -m aitriage && \
    mkdir -p /project && chown -R aitriage:aitriage /project

# Note: For GitHub Actions compatibility (writing to host-mounted GITHUB_WORKSPACE),
# we run as root by default. You can run as non-root locally using `docker run --user 1000`.
# USER aitriage
WORKDIR /project

EXPOSE 8080

ENTRYPOINT ["aitriage"]
CMD ["web", "--runtime", "native", "--port", "8080", "--host-prefix", "/workspace"]
