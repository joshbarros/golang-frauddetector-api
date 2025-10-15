.PHONY: all test coverage coverage-html bench clean lint fmt vet security help

# Variables
GOTEST_FLAGS = -v -race -timeout=30s
COVERAGE_FILE = coverage.out
COVERAGE_HTML = coverage.html
BENCH_FILE = benchmark.txt

# Default target
all: fmt vet lint test ## Run all checks and tests

test: ## Run all tests
	@echo "Running tests..."
	@go test $(GOTEST_FLAGS) ./...

coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test $(GOTEST_FLAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo "\nCoverage Summary:"
	@go tool cover -func=$(COVERAGE_FILE) | grep -E '^total:' || go tool cover -func=$(COVERAGE_FILE)

coverage-html: coverage ## Generate HTML coverage report
	@echo "Generating HTML coverage report..."
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

coverage-check: coverage ## Check if coverage meets threshold (80%)
	@echo "Checking coverage threshold..."
	@coverage=$$(go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print substr($$3, 1, length($$3)-1)}'); \
	echo "Total coverage: $$coverage%"; \
	if [ $$(echo "$$coverage < 80" | bc -l) -eq 1 ]; then \
		echo "❌ Coverage is below 80% threshold"; \
		exit 1; \
	else \
		echo "✅ Coverage meets threshold"; \
	fi

bench: ## Run benchmarks
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -benchtime=10s ./... | tee $(BENCH_FILE)
	@echo "Benchmark results saved to: $(BENCH_FILE)"

bench-compare: ## Compare benchmark results
	@echo "Running benchmark comparison..."
	@if [ -f $(BENCH_FILE) ]; then \
		mv $(BENCH_FILE) $(BENCH_FILE).old; \
	fi
	@go test -bench=. -benchmem -benchtime=10s ./... | tee $(BENCH_FILE)
	@if [ -f $(BENCH_FILE).old ]; then \
		benchstat $(BENCH_FILE).old $(BENCH_FILE); \
	fi

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	@go test $(GOTEST_FLAGS) -tags=integration ./tests/integration/...

test-unit: ## Run only unit tests
	@echo "Running unit tests..."
	@go test $(GOTEST_FLAGS) -short ./...

test-verbose: ## Run tests with verbose output
	@echo "Running tests with verbose output..."
	@go test -v -count=1 ./...

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -s -w .

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

lint: ## Run golangci-lint
	@echo "Running linter..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "golangci-lint not installed. Install with:"; \
		echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

security: ## Run security scan
	@echo "Running security scan..."
	@if command -v gosec > /dev/null; then \
		gosec -fmt json -out gosec-report.json ./...; \
		echo "Security report generated: gosec-report.json"; \
	else \
		echo "gosec not installed. Install with:"; \
		echo "  go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify
	@go mod tidy

deps-update: ## Update dependencies to latest versions
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

clean: ## Clean build artifacts and test cache
	@echo "Cleaning..."
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML) $(BENCH_FILE)
	@go clean -testcache
	@echo "Cleaned test cache and coverage files"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t fraud-detection:latest .

docker-test: ## Run tests in Docker
	@echo "Running tests in Docker..."
	@docker run --rm -v $(PWD):/app -w /app golang:1.22-alpine go test $(GOTEST_FLAGS) ./...

ci: fmt vet lint test coverage-check ## Run CI pipeline locally
	@echo "✅ All CI checks passed!"

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Performance profiling targets
profile-cpu: ## Generate CPU profile
	@echo "Generating CPU profile..."
	@go test -cpuprofile=cpu.prof -bench=. ./...
	@go tool pprof -http=:8080 cpu.prof

profile-mem: ## Generate memory profile
	@echo "Generating memory profile..."
	@go test -memprofile=mem.prof -bench=. ./...
	@go tool pprof -http=:8080 mem.prof

# Test coverage for specific packages
coverage-pkg: ## Run coverage for specific package (use PKG=./internal/detector)
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make coverage-pkg PKG=./internal/detector"; \
		exit 1; \
	fi
	@echo "Running coverage for package: $(PKG)"
	@go test $(GOTEST_FLAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(PKG)
	@go tool cover -func=$(COVERAGE_FILE)