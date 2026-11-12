# ==============================================================================
# AITriage - Premium Build System
# ==============================================================================

BINARY_NAME=aitriage
VERSION=1.5.0
LDFLAGS="-s -w -X main.Version=${VERSION}"

.PHONY: all build test clean format install release launch docker-build docker-tui docker-web docker-scan build-web sync-web web-up up enterprise-up down

# Colors
BLUE=\033[34m
GREEN=\033[32m
RESET=\033[0m

all: format test build

build:
	@echo "$(BLUE)Building AITriage binary...$(RESET)"
	@go build -ldflags $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/aitriage
	@echo "$(GREEN)Build complete: bin/$(BINARY_NAME)$(RESET)"

test:
	@echo "$(BLUE)Executing test suite...$(RESET)"
	@go test ./... -v

lint:
	@echo "$(BLUE)Running golangci-lint...$(RESET)"
	@golangci-lint run ./...

clean:
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	@rm -rf bin/
	@go clean

format:
	@echo "$(BLUE)Formatting Go sources...$(RESET)"
	@go fmt ./...
	@if command -v goimports > /dev/null; then goimports -w .; fi
	@if command -v gofumpt > /dev/null; then gofumpt -w .; fi
	@if command -v gci > /dev/null; then gci write --section Standard --section Default --section "Prefix(github.com/dodobrands/aitriage)" .; fi
	@echo "$(BLUE)Formatting Web sources...$(RESET)"
	@if [ -d "web" ]; then \
		cd web && npm run format || true; \
	fi
	@echo "$(GREEN)Code formatting and structural verification complete.$(RESET)"

install: build
	@echo "$(BLUE)Installing binary to GOPATH...$(RESET)"
	@cp bin/$(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)

release:
	@echo "$(BLUE)Running release pipeline...$(RESET)"
	@goreleaser release --snapshot --clean

# ─── Web UI ───────────────────────────────────────────────────────────────────

build-web:
	@echo "$(BLUE)Building Web frontend...$(RESET)"
	@cd web && npm install && npm run build

sync-web: build-web
	@echo "$(BLUE)Synchronizing Web assets...$(RESET)"
	@mkdir -p internal/server/ui/dist
	@cp -r web/dist/* internal/server/ui/dist/
	@echo "$(GREEN)Assets synchronized to internal/server/ui/dist$(RESET)"

web-up: up

# ─── Docker ───────────────────────────────────────────────────────────────────

# 🚀 ONE COMMAND: Build frontend + backend inside Docker & launch
# Usage: make launch
launch:
	@echo "$(BLUE)🚀 Building & launching AITriage (frontend + backend in Docker)...$(RESET)"
	@docker compose up -d --build web
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║  AITriage is running!                                ║$(RESET)"
	@echo "$(GREEN)║  Web UI:  http://localhost:8080                      ║$(RESET)"
	@echo "$(GREEN)║  Health:  http://localhost:8080/api/health            ║$(RESET)"
	@echo "$(GREEN)║                                                      ║$(RESET)"
	@echo "$(GREEN)║  Default login:  admin / admin                       ║$(RESET)"
	@echo "$(GREEN)║  Stop:  make down                                    ║$(RESET)"
	@echo "$(GREEN)╚══════════════════════════════════════════════════════╝$(RESET)"

up: sync-web
	@echo "$(BLUE)Starting AITriage Enterprise Stack...$(RESET)"
	@docker compose up -d --build web
	@echo "$(GREEN)AITriage is running! Web UI: http://localhost:8080$(RESET)"

enterprise-up: sync-web
	@echo "$(BLUE)Starting AITriage Enterprise Stack (Production)...$(RESET)"
	@docker compose up -d --build
	@echo "$(GREEN)AITriage Enterprise is running! Web UI: http://localhost:8080$(RESET)"

down:
	@echo "$(BLUE)Stopping AITriage Enterprise Stack...$(RESET)"
	@docker compose down
	@echo "$(GREEN)AITriage has been stopped.$(RESET)"


docker-build:
	@./scripts/build_docker.sh

# Interactive TUI with all scanners (semgrep, trivy, gitleaks, bandit)
# Usage: make docker-tui                     ← scans current directory
#        make docker-tui PROJECT=/path/to/app ← scans specific project
docker-tui: docker-build
	@echo "🚀 Launching TUI in Docker..."
	@docker run --rm -it \
		-e GEMINI_API_KEY=$${GEMINI_API_KEY:-} \
		-e TERM=xterm-256color \
		-v $${PROJECT:-$(PWD)}:/project:ro \
		aitriage:latest scan /project -i

# Web dashboard in browser at http://localhost:8080
# Usage: make docker-web                     ← scans current directory
#        make docker-web PROJECT=/path/to/app ← scans specific project
docker-web: sync-web docker-build
	@echo "🌐 Starting Web UI → http://localhost:8080"
	@docker run --rm -it \
		-e GEMINI_API_KEY=$${GEMINI_API_KEY:-} \
		-p 8080:8080 \
		-v $${PROJECT:-$(PWD)}:/project:ro \
		aitriage:latest web --port 8080 --host-prefix /project

# CLI scan with JSON output (for CI/CD)
# Usage: make docker-scan                     ← scans current directory
#        make docker-scan PROJECT=/path/to/app ← scans specific project
docker-scan: docker-build
	@docker run --rm \
		-v $${PROJECT:-$(PWD)}:/project:ro \
		aitriage:latest scan /project --format json

