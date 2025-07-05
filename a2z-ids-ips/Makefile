# A2Z IDS/IPS Makefile
# Version: 1.0.0

.PHONY: help build clean test lint format install dev docs docker k8s benchmark

# Variables
VERSION ?= 1.0.0
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_FLAGS = -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Docker settings
DOCKER_REGISTRY ?= ghcr.io/a2z-soc
DOCKER_TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64

# Kubernetes settings
KUBE_NAMESPACE ?= a2z-ids
KUBE_CONTEXT ?= default

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)A2Z IDS/IPS Build System$(NC)"
	@echo "$(YELLOW)Available commands:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# Development Commands
# =============================================================================

install: ## Install all dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	@echo "Installing Rust dependencies..."
	cd core-engine && cargo fetch
	@echo "Installing Go dependencies..."
	cd management-api && go mod download
	@echo "Installing Node.js dependencies..."
	cd web-interface && npm install
	@echo "Installing Python dependencies..."
	cd ml-engine && pip install -r requirements.txt
	@echo "$(GREEN)Dependencies installed successfully!$(NC)"

dev: ## Start development environment
	@echo "$(GREEN)Starting A2Z IDS/IPS development environment...$(NC)"
	docker-compose up -d postgres redis clickhouse
	@echo "Waiting for databases to be ready..."
	@sleep 10
	docker-compose up --build

dev-stop: ## Stop development environment
	@echo "$(YELLOW)Stopping development environment...$(NC)"
	docker-compose down

dev-clean: ## Clean development environment
	@echo "$(YELLOW)Cleaning development environment...$(NC)"
	docker-compose down -v
	docker system prune -f

# =============================================================================
# Build Commands
# =============================================================================

build: build-core build-api build-web build-ml ## Build all components

build-core: ## Build Rust core engine
	@echo "$(GREEN)Building core engine...$(NC)"
	cd core-engine && cargo build --release

build-api: ## Build Go management API
	@echo "$(GREEN)Building management API...$(NC)"
	cd management-api && go build $(BUILD_FLAGS) -o bin/a2z-ids-api ./cmd/api

build-web: ## Build React web interface
	@echo "$(GREEN)Building web interface...$(NC)"
	cd web-interface && npm run build

build-ml: ## Build Python ML engine
	@echo "$(GREEN)Building ML engine...$(NC)"
	cd ml-engine && python setup.py build

build-all: clean install build ## Clean, install dependencies, and build all

# =============================================================================
# Testing Commands
# =============================================================================

test: test-core test-api test-web ## Run all tests

test-core: ## Run Rust core engine tests
	@echo "$(GREEN)Running core engine tests...$(NC)"
	cd core-engine && cargo test --all-features

test-api: ## Run Go API tests
	@echo "$(GREEN)Running API tests...$(NC)"
	cd management-api && go test -v ./...

test-web: ## Run React web interface tests
	@echo "$(GREEN)Running web interface tests...$(NC)"
	cd web-interface && npm test

test-ml: ## Run Python ML engine tests
	@echo "$(GREEN)Running ML engine tests...$(NC)"
	cd ml-engine && python -m pytest tests/

test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(NC)"
	./scripts/run-integration-tests.sh

benchmark: ## Run performance benchmarks
	@echo "$(GREEN)Running benchmarks...$(NC)"
	cd core-engine && cargo bench
	cd management-api && go test -bench=. ./...

# =============================================================================
# Code Quality Commands
# =============================================================================

lint: lint-core lint-api lint-web lint-ml ## Run all linters

lint-core: ## Lint Rust code
	@echo "$(GREEN)Linting core engine...$(NC)"
	cd core-engine && cargo clippy --all-targets --all-features -- -D warnings

lint-api: ## Lint Go code
	@echo "$(GREEN)Linting API code...$(NC)"
	cd management-api && golangci-lint run

lint-web: ## Lint TypeScript/React code
	@echo "$(GREEN)Linting web interface...$(NC)"
	cd web-interface && npm run lint

lint-ml: ## Lint Python code
	@echo "$(GREEN)Linting ML engine...$(NC)"
	cd ml-engine && pylint src/ && black --check src/ && isort --check-only src/

format: format-core format-api format-web format-ml ## Format all code

format-core: ## Format Rust code
	@echo "$(GREEN)Formatting core engine...$(NC)"
	cd core-engine && cargo fmt

format-api: ## Format Go code
	@echo "$(GREEN)Formatting API code...$(NC)"
	cd management-api && gofmt -w . && goimports -w .

format-web: ## Format TypeScript/React code
	@echo "$(GREEN)Formatting web interface...$(NC)"
	cd web-interface && npm run format

format-ml: ## Format Python code
	@echo "$(GREEN)Formatting ML engine...$(NC)"
	cd ml-engine && black src/ && isort src/

# =============================================================================
# Docker Commands
# =============================================================================

docker: docker-build ## Build all Docker images

docker-build: ## Build Docker images
	@echo "$(GREEN)Building Docker images...$(NC)"
	docker build -t $(DOCKER_REGISTRY)/a2z-ids-core:$(DOCKER_TAG) ./core-engine
	docker build -t $(DOCKER_REGISTRY)/a2z-ids-api:$(DOCKER_TAG) ./management-api
	docker build -t $(DOCKER_REGISTRY)/a2z-ids-web:$(DOCKER_TAG) ./web-interface
	docker build -t $(DOCKER_REGISTRY)/a2z-ids-ml:$(DOCKER_TAG) ./ml-engine
	docker build -t $(DOCKER_REGISTRY)/a2z-ids-alerts:$(DOCKER_TAG) ./alert-processor

docker-push: ## Push Docker images to registry
	@echo "$(GREEN)Pushing Docker images...$(NC)"
	docker push $(DOCKER_REGISTRY)/a2z-ids-core:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/a2z-ids-api:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/a2z-ids-web:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/a2z-ids-ml:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/a2z-ids-alerts:$(DOCKER_TAG)

docker-multiarch: ## Build multi-architecture Docker images
	@echo "$(GREEN)Building multi-architecture Docker images...$(NC)"
	docker buildx build --platform $(PLATFORMS) -t $(DOCKER_REGISTRY)/a2z-ids-core:$(DOCKER_TAG) --push ./core-engine
	docker buildx build --platform $(PLATFORMS) -t $(DOCKER_REGISTRY)/a2z-ids-api:$(DOCKER_TAG) --push ./management-api
	docker buildx build --platform $(PLATFORMS) -t $(DOCKER_REGISTRY)/a2z-ids-web:$(DOCKER_TAG) --push ./web-interface
	docker buildx build --platform $(PLATFORMS) -t $(DOCKER_REGISTRY)/a2z-ids-ml:$(DOCKER_TAG) --push ./ml-engine

# =============================================================================
# Kubernetes Commands
# =============================================================================

k8s-deploy: ## Deploy to Kubernetes
	@echo "$(GREEN)Deploying to Kubernetes...$(NC)"
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/configmap.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/secrets.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/postgres.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/redis.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/clickhouse.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/core-engine.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/management-api.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/web-interface.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/ml-engine.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/alert-processor.yaml -n $(KUBE_NAMESPACE)
	kubectl apply -f k8s/ingress.yaml -n $(KUBE_NAMESPACE)

k8s-status: ## Check Kubernetes deployment status
	@echo "$(GREEN)Checking Kubernetes status...$(NC)"
	kubectl get pods -n $(KUBE_NAMESPACE)
	kubectl get services -n $(KUBE_NAMESPACE)
	kubectl get ingress -n $(KUBE_NAMESPACE)

k8s-logs: ## View Kubernetes logs
	@echo "$(GREEN)Viewing Kubernetes logs...$(NC)"
	kubectl logs -f -l app=a2z-ids-core -n $(KUBE_NAMESPACE)

k8s-delete: ## Delete Kubernetes deployment
	@echo "$(YELLOW)Deleting Kubernetes deployment...$(NC)"
	kubectl delete namespace $(KUBE_NAMESPACE)

# =============================================================================
# Configuration Commands
# =============================================================================

config-validate: ## Validate configuration
	@echo "$(GREEN)Validating configuration...$(NC)"
	./scripts/validate-config.sh

config-generate: ## Generate sample configuration
	@echo "$(GREEN)Generating sample configuration...$(NC)"
	cp config/config.yaml config/config.sample.yaml

rules-update: ## Update detection rules
	@echo "$(GREEN)Updating detection rules...$(NC)"
	./scripts/update-rules.sh

rules-validate: ## Validate detection rules
	@echo "$(GREEN)Validating detection rules...$(NC)"
	./scripts/validate-rules.sh

# =============================================================================
# Documentation Commands
# =============================================================================

docs: ## Generate documentation
	@echo "$(GREEN)Generating documentation...$(NC)"
	cd core-engine && cargo doc --no-deps
	cd management-api && godoc -http=:6060 &
	cd web-interface && npm run docs
	@echo "$(GREEN)Documentation generated!$(NC)"
	@echo "  - Rust docs: file://$(PWD)/core-engine/target/doc/a2z_ids_core/index.html"
	@echo "  - Go docs: http://localhost:6060"
	@echo "  - Web docs: $(PWD)/web-interface/docs"

docs-serve: ## Serve documentation
	@echo "$(GREEN)Serving documentation...$(NC)"
	python3 -m http.server 8000 -d docs/

# =============================================================================
# Database Commands
# =============================================================================

db-migrate: ## Run database migrations
	@echo "$(GREEN)Running database migrations...$(NC)"
	cd management-api && go run cmd/migrate/main.go up

db-seed: ## Seed database with sample data
	@echo "$(GREEN)Seeding database...$(NC)"
	./scripts/seed-database.sh

db-backup: ## Backup database
	@echo "$(GREEN)Backing up database...$(NC)"
	./scripts/backup-database.sh

db-restore: ## Restore database from backup
	@echo "$(GREEN)Restoring database...$(NC)"
	./scripts/restore-database.sh

# =============================================================================
# Monitoring Commands
# =============================================================================

monitoring-up: ## Start monitoring stack
	@echo "$(GREEN)Starting monitoring stack...$(NC)"
	docker-compose -f monitoring/docker-compose.monitoring.yml up -d

monitoring-down: ## Stop monitoring stack
	@echo "$(YELLOW)Stopping monitoring stack...$(NC)"
	docker-compose -f monitoring/docker-compose.monitoring.yml down

logs: ## View application logs
	@echo "$(GREEN)Viewing logs...$(NC)"
	docker-compose logs -f

metrics: ## View metrics
	@echo "$(GREEN)Opening metrics dashboard...$(NC)"
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3001 (admin/admin_password)"

# =============================================================================
# Security Commands
# =============================================================================

security-scan: ## Run security scans
	@echo "$(GREEN)Running security scans...$(NC)"
	cd core-engine && cargo audit
	cd management-api && gosec ./...
	cd web-interface && npm audit
	cd ml-engine && safety check

vulnerability-scan: ## Scan for vulnerabilities
	@echo "$(GREEN)Scanning for vulnerabilities...$(NC)"
	trivy filesystem .

secrets-scan: ## Scan for secrets
	@echo "$(GREEN)Scanning for secrets...$(NC)"
	gitleaks detect --source . --verbose

# =============================================================================
# Release Commands
# =============================================================================

release: ## Create a new release
	@echo "$(GREEN)Creating release $(VERSION)...$(NC)"
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	$(MAKE) docker-build docker-push
	$(MAKE) docs

release-notes: ## Generate release notes
	@echo "$(GREEN)Generating release notes...$(NC)"
	./scripts/generate-release-notes.sh $(VERSION)

# =============================================================================
# Utility Commands
# =============================================================================

clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	cd core-engine && cargo clean
	cd management-api && go clean && rm -rf bin/
	cd web-interface && rm -rf dist/ build/
	cd ml-engine && rm -rf build/ dist/ *.egg-info/
	docker system prune -f

deps-update: ## Update dependencies
	@echo "$(GREEN)Updating dependencies...$(NC)"
	cd core-engine && cargo update
	cd management-api && go get -u ./...
	cd web-interface && npm update
	cd ml-engine && pip-tools compile --upgrade requirements.in

size-analysis: ## Analyze binary sizes
	@echo "$(GREEN)Analyzing binary sizes...$(NC)"
	cd core-engine && cargo bloat --release --crates
	cd management-api && go tool nm bin/a2z-ids-api | wc -l

setup-dev: ## Setup development environment
	@echo "$(GREEN)Setting up development environment...$(NC)"
	./scripts/setup-dev-env.sh

setup-prod: ## Setup production environment
	@echo "$(GREEN)Setting up production environment...$(NC)"
	./scripts/setup-prod-env.sh

health-check: ## Check system health
	@echo "$(GREEN)Checking system health...$(NC)"
	curl -f http://localhost:8080/health || echo "$(RED)API not responding$(NC)"
	curl -f http://localhost:3000 || echo "$(RED)Web interface not responding$(NC)"

# =============================================================================
# Performance Commands
# =============================================================================

profile: ## Profile application performance
	@echo "$(GREEN)Profiling application...$(NC)"
	cd core-engine && cargo build --release && perf record --call-graph=dwarf target/release/a2z-ids
	cd management-api && go tool pprof http://localhost:8080/debug/pprof/profile

stress-test: ## Run stress tests
	@echo "$(GREEN)Running stress tests...$(NC)"
	./scripts/stress-test.sh

load-test: ## Run load tests
	@echo "$(GREEN)Running load tests...$(NC)"
	./scripts/load-test.sh

# =============================================================================
# Integration Commands
# =============================================================================

soc-integration: ## Test A2Z SOC integration
	@echo "$(GREEN)Testing A2Z SOC integration...$(NC)"
	./scripts/test-soc-integration.sh

splunk-integration: ## Test Splunk integration
	@echo "$(GREEN)Testing Splunk integration...$(NC)"
	./scripts/test-splunk-integration.sh

elastic-integration: ## Test Elasticsearch integration
	@echo "$(GREEN)Testing Elasticsearch integration...$(NC)"
	./scripts/test-elastic-integration.sh

# =============================================================================
# Default target
# =============================================================================

.DEFAULT_GOAL := help 