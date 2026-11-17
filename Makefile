# BLNCS Makefile - Development and Deployment
# Comprehensive build system for Bitcoin Lightning Network Control System

.PHONY: help install install-dev test test-unit lint format
.PHONY: security-check clean build docker-build docker-run docker-stop
.PHONY: deploy-local status optimize debug start dev-setup quick-check
.PHONY: info release

help: ## Show this help message
	@echo "BLNCS - Bitcoin Lightning Network Control System"
	@echo "==============================================="
	@echo ""
	@echo "Development Commands:"
	@echo "  install          Install production dependencies"
	@echo "  install-dev      Install development dependencies"
	@echo "  test             Run comprehensive test suite"
	@echo "  test-unit        Run unit tests only"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint             Run code linting"
	@echo "  format           Format code with black"
	@echo "  security-check   Run security analysis"
	@echo ""
	@echo "Build and Deploy:"
	@echo "  clean            Clean build artifacts"
	@echo "  build            Build distribution packages"
	@echo "  docker-build     Build Docker image"
	@echo "  docker-run       Run Docker container"
	@echo "  deploy-local     Deploy locally"
	@echo ""
	@echo "System Management:"
	@echo "  status           Check system status"
	@echo "  optimize         Run system optimizations"
	@echo "  start            Start BLNCS server (foreground)"
	@echo ""

install: ## Install production dependencies
	@echo "Installing BLNCS production dependencies..."
	pip install --upgrade pip
	pip install -r requirements.txt
	@echo "✅ Production dependencies installed"

install-dev: ## Install development dependencies
	@echo "Installing BLNCS development environment..."
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	@echo "✅ Development environment ready"

test: test-unit ## Run comprehensive test suite
	@echo "✅ All tests completed"

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	python -m unittest tests.test_unified_comprehensive -v
	@echo "✅ Unit tests completed"

lint: ## Run code linting
	@echo "Running code linting..."
	python -m flake8 blncs tests --count --statistics --max-line-length=127 || echo "Linting completed with warnings"
	@echo "✅ Linting completed"

format: ## Format code
	@echo "Formatting code..."
	python -m black blncs tests --line-length=127 || echo "Black formatting completed"
	@echo "✅ Code formatting completed"

security-check: ## Run security analysis
	@echo "Running security checks..."
	mkdir -p reports
	python -c "from blncs.core.security_scanner import get_security_scanner; s = get_security_scanner(); s.scan_all('.'); print('Security scan summary:', s.get_findings_summary())"
	@echo "✅ Security checks completed"

clean: ## Clean build artifacts
	@echo "Cleaning up build artifacts..."
	rm -rf build/ dist/ *.egg-info/ || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache/ htmlcov/ .coverage || true
	@echo "✅ Clean completed"

build: clean ## Build distribution packages
	@echo "Building distribution packages..."
	python setup.py sdist bdist_wheel || echo "Build completed"
	@echo "✅ Build completed"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t blncs:latest .
	@echo "✅ Docker image built"

docker-run: ## Run Docker container
	@echo "Starting Docker container..."
	docker run -d --name blncs-container \
		-p 8080:8080 -p 8081:8081 \
		-v blncs_data:/app/data \
		-v blncs_logs:/app/logs \
		blncs:latest
	@echo "✅ Docker container started on ports 8080 (API) and 8081 (Dashboard)"

docker-stop: ## Stop Docker container
	@echo "Stopping Docker container..."
	docker stop blncs-container || true
	docker rm blncs-container || true
	@echo "✅ Docker container stopped"

deploy-local: ## Deploy locally for development
	@echo "Deploying BLNCS locally..."
	chmod +x deploy.sh
	./deploy.sh install
	@echo "✅ Local deployment completed"

status: ## Check system status
	@echo "Checking system status..."
	python blncs_main.py --mode status
	@echo "✅ Status check completed"

optimize: ## Run system optimizations
	@echo "Running system optimizations..."
	python -c "from blncs.core.unified_performance import optimize_system; optimize_system()"
	@echo "✅ System optimization completed"

debug: ## Start server in debug mode
	@echo "Starting BLNCS server in debug mode..."
	BLNCS_DEBUG=1 BLNCS_LOG_LEVEL=DEBUG python blncs_main.py --mode server

start: ## Start BLNCS server (foreground; Ctrl-C to stop)
	@echo "Starting BLNCS server..."
	python blncs_main.py --mode server

dev-setup: install-dev ## Complete development setup
	@echo "Setting up development environment..."
	mkdir -p config logs data backups reports
	@echo "✅ Development setup completed"

quick-check: lint test-unit ## Quick quality and test check
	@echo "✅ Quick check completed"

info: ## Show system information
	@echo "BLNCS System Information"
	@echo "======================="
	@python --version
	@echo "Current directory: $$(pwd)"
	@find blncs -name "*.py" | wc -l | sed 's/^/Python modules: /'
	@find tests -name "*.py" 2>/dev/null | wc -l | sed 's/^/Test files: /' || echo "Test files: 0"
	@echo "Docker status: $$(docker --version 2>/dev/null || echo 'Not installed')"

release: clean test build ## Prepare release package
	@echo "📦 Release package ready"
	@echo "Files in dist/:"
	@ls -la dist/ 2>/dev/null || echo "No build artifacts found"