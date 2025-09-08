# BLRCS Makefile - Simple and practical
# Following the philosophy: "Make it work, make it right, make it fast"

.PHONY: help install test clean info health check

help:
	@echo "BLRCS - Bitcoin Lightning Network Control System"
	@echo ""
	@echo "Available commands:"
	@echo "  install     Install dependencies"
	@echo "  test        Run basic tests"
	@echo "  clean       Clean up temporary files"
	@echo "  info        Show Lightning node info"
	@echo "  balance     Show Lightning node balance"
	@echo "  channels    List Lightning channels"
	@echo "  health      Test Lightning node connection"
	@echo "  check       Check system status"

install:
	@echo "Installing BLRCS dependencies..."
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"

test:
	@echo "Running basic tests..."
	python3 test_simple.py

clean:
	@echo "Cleaning up..."
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete -type d
	find . -name ".pytest_cache" -delete -type d
	rm -rf build/ dist/ *.egg-info/
	@echo "✓ Cleanup complete"

info:
	@echo "Getting Lightning node information..."
	python3 blrcs_simple.py info

balance:
	@echo "Getting balance information..."
	python3 blrcs_simple.py balance

channels:
	@echo "Listing Lightning channels..."
	python3 blrcs_simple.py channels

health:
	@echo "Testing Lightning node connection..."
	python3 blrcs_simple.py test

check: health info
	@echo "✓ System check complete"