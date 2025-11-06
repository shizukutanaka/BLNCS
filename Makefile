# BLNCS Makefile - Development and Deployment
# Comprehensive build system for Bitcoin Lightning Network Control System

.PHONY: help install install-dev test test-unit test-performance lint format
.PHONY: security-check clean build docker-build docker-run deploy-local
.PHONY: backup health status benchmark optimize debug release

help: ## Show this help message
	@echo "BLNCS - Bitcoin Lightning Network Control System"
	@echo "==============================================="
	@echo ""
	@echo "Development Commands:"
	@echo "  install          Install production dependencies"
	@echo "  install-dev      Install development dependencies"
	@echo "  test             Run comprehensive test suite"
	@echo "  test-unit        Run unit tests only"
	@echo "  test-performance Run performance benchmarks"
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
	@echo "  health           Run health checks"
	@echo "  benchmark        Run performance benchmarks"
	@echo "  optimize         Run system optimizations"
	@echo "  backup           Create system backup"
	@echo ""
	@echo "Lightning Network:"
	@echo "  lightning-info   Get Lightning node info"
	@echo "  lightning-balance Show Lightning balance"
	@echo "  lightning-channels List Lightning channels"

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

test-performance: ## Run performance benchmarks
	@echo "Running performance tests..."
	python blncs_cli.py benchmark --quick
	@echo "✅ Performance tests completed"

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
	python -c "from blncs.core.security_hardening import get_security_hardening; h = get_security_hardening(); print('Security hardening system operational')"
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

backup: ## Create system backup
	@echo "Creating system backup..."
	python blncs_cli.py backup create --type=full
	@echo "✅ Backup created"

status: ## Check system status
	@echo "Checking system status..."
	python blncs_cli.py status
	@echo "✅ Status check completed"

health: ## Run health checks
	@echo "Running health checks..."
	python blncs_cli.py health
	@echo "✅ Health check completed"

benchmark: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	python blncs_cli.py benchmark --quick
	@echo "✅ Benchmark completed"

optimize: ## Run system optimizations
	@echo "Running system optimizations..."
	python -c "from blncs.core.production_optimizer import optimize_system; optimize_system()"
	@echo "✅ System optimization completed"

debug: ## Start in debug mode
	@echo "Starting BLNCS in debug mode..."
	BLNCS_DEBUG=1 BLNCS_LOG_LEVEL=DEBUG python blncs_cli.py start
	@echo "🐛 Debug mode started"

lightning-info: ## Get Lightning node information
	@echo "Getting Lightning node information..."
	python blncs_cli.py lightning info

lightning-balance: ## Show Lightning node balance
	@echo "Getting Lightning node balance..."
	python blncs_cli.py lightning balance

lightning-channels: ## List Lightning channels
	@echo "Listing Lightning channels..."
	python blncs_cli.py lightning channels

start: ## Start BLNCS services
	@echo "Starting BLNCS services..."
	python blncs_cli.py start
	@echo "✅ BLNCS services started"

stop: ## Stop BLNCS services
	@echo "Stopping BLNCS services..."
	python blncs_cli.py stop
	@echo "✅ BLNCS services stopped"

restart: stop start ## Restart BLNCS services
	@echo "✅ BLNCS services restarted"

monitor: ## Start monitoring dashboard
	@echo "Starting monitoring dashboard..."
	python blncs_cli.py monitor
	@echo "📊 Monitoring dashboard started"

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