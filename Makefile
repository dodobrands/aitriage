# ==============================================================================
# AITriage developer Makefile. Run `make help` to list the targets.
# ==============================================================================

BINARY_NAME = aitriage
# Local builds identify as "dev" and use the rolling scanner image
# (ghcr.io/dodobrands/aitriage:v1). Override to pin one release's image, e.g.
# `make build VERSION=v1.13.0`. Tag releases are built by
# .github/workflows/release.yml, not by this Makefile.
VERSION ?= dev
LDFLAGS = -s -w -X main.Version=$(VERSION)
# Local image built by docker-build and used by the docker-* targets.
IMAGE ?= aitriage:latest
# Project scanned by docker-tui, docker-web and docker-scan.
PROJECT ?= $(CURDIR)

.DEFAULT_GOAL := all
.PHONY: help all build test lint clean format install release build-web sync-web web-up launch up enterprise-up down docker-build docker-tui docker-web docker-scan

# Colors
BLUE = \033[34m
GREEN = \033[32m
RESET = \033[0m

help: ## List the available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: format test build ## Format, test and build (default target)

build: ## Build bin/aitriage (run sync-web first to embed the real Web UI)
	@echo "$(BLUE)Building AITriage binary...$(RESET)"
	@go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/aitriage
	@echo "$(GREEN)Build complete: bin/$(BINARY_NAME)$(RESET)"

test: ## Run the Go test suite
	@echo "$(BLUE)Running Go tests...$(RESET)"
	@go test ./... -v

lint: ## Run golangci-lint
	@echo "$(BLUE)Running golangci-lint...$(RESET)"
	@golangci-lint run ./...

clean: ## Remove bin/ and go clean output
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	@rm -rf bin/
	@go clean

format: ## Format Go sources, then run the web formatter (failures ignored)
	@echo "$(BLUE)Formatting Go sources...$(RESET)"
	@go fmt ./...
	@if command -v goimports > /dev/null; then goimports -w .; fi
	@if command -v gofumpt > /dev/null; then gofumpt -w .; fi
	@if command -v gci > /dev/null; then gci write --section Standard --section Default --section "Prefix(github.com/dodobrands/aitriage)" .; fi
	@echo "$(BLUE)Formatting Web sources...$(RESET)"
	@if [ -d "web" ]; then \
	    cd web && npm run format || true; \
	fi
	@echo "$(GREEN)Formatting complete.$(RESET)"

install: build ## Copy bin/aitriage into GOBIN (default: GOPATH/bin)
	@dest="$$(go env GOBIN)"; [ -n "$$dest" ] || dest="$$(go env GOPATH)/bin"; \
	    mkdir -p "$$dest" && cp bin/$(BINARY_NAME) "$$dest/$(BINARY_NAME)" && \
	    echo "$(GREEN)Installed $$dest/$(BINARY_NAME)$(RESET)"

# tree-sitter needs CGO, so this builds only the host platform: cross-compiling
# every platform would need C toolchains this target does not assume.
release: ## GoReleaser snapshot build for this machine (publishes nothing)
	@echo "$(BLUE)Running GoReleaser snapshot build for the host platform...$(RESET)"
	@goreleaser build --snapshot --clean --single-target

# ─── Web UI ───────────────────────────────────────────────────────────────────

build-web: ## Build the web frontend from the lockfile (npm ci + npm run build)
	@echo "$(BLUE)Building Web frontend...$(RESET)"
	@cd web && npm ci && npm run build

sync-web: build-web ## Build the frontend and copy web/dist into internal/server/ui/dist
	@echo "$(BLUE)Synchronizing Web assets...$(RESET)"
	@mkdir -p internal/server/ui/dist
	@cp -r web/dist/* internal/server/ui/dist/
	@echo "$(GREEN)Assets synchronized to internal/server/ui/dist$(RESET)"

web-up: up ## Alias of up

# ─── Docker Compose (docker-compose.yaml) ─────────────────────────────────────
# The image build compiles the Web UI itself (see the Dockerfile).

launch: ## Build and start the compose web service, then print its URLs
	@echo "$(BLUE)Building and starting the AITriage web service (docker compose)...$(RESET)"
	@docker compose up -d --build web
	@echo ""
	@echo "$(GREEN)AITriage web service started.$(RESET)"
	@echo "  Web UI:  http://localhost:8080"
	@echo "  Health:  http://localhost:8080/api/health"
	@echo "  Login:   none. The dashboard has no authentication; keep it local."
	@echo "  Stop:    make down"

up: ## Build and start the compose web service
	@echo "$(BLUE)Starting the AITriage web service (docker compose)...$(RESET)"
	@docker compose up -d --build web
	@echo "$(GREEN)AITriage web service started: http://localhost:8080$(RESET)"

enterprise-up: up ## Alias of up (kept for existing docs and scripts)

down: ## Stop and remove the compose services
	@echo "$(BLUE)Stopping AITriage (docker compose)...$(RESET)"
	@docker compose down
	@echo "$(GREEN)AITriage has been stopped.$(RESET)"

# ─── Docker (local image) ─────────────────────────────────────────────────────
# PROJECT defaults to the current directory: make docker-tui PROJECT=/path/to/app

docker-build: ## Build the local scanner image (aitriage:latest)
	@echo "$(BLUE)Building $(IMAGE)...$(RESET)"
	@docker build --build-arg AITRIAGE_VERSION=$(VERSION) -t $(IMAGE) .

docker-tui: docker-build ## Interactive TUI scan of PROJECT in the local image
	@docker run --rm -it \
	    -e GEMINI_API_KEY \
	    -e TERM=xterm-256color \
	    -v "$(PROJECT):/project:ro" \
	    $(IMAGE) scan /project -i

# Uses the CLI's managed Web launcher (the same path as `aitriage web`) with the
# local image: PROJECT is mounted read-only, state is written to
# PROJECT/aitriage-reports/, and the port is published on 127.0.0.1 only.
docker-web: docker-build build ## Web UI for PROJECT from the local image on http://localhost:8080
	@AITRIAGE_IMAGE=$(IMAGE) ./bin/$(BINARY_NAME) web --project "$(PROJECT)" --port 8080

docker-scan: docker-build ## JSON scan of PROJECT in the local image (for CI/CD)
	@docker run --rm \
	    -v "$(PROJECT):/project:ro" \
	    $(IMAGE) scan /project --format json
