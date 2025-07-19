SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help dev start install clean test

help: ## Show this help message
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

dev: ## Start development server with auto-reload
	@echo "🚀 Starting FastAPI server in development mode..."
	PATH="$$HOME/.local/bin:$$PATH" uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

start: ## Start production server
	@echo "🚀 Starting FastAPI server in production mode..."
	PATH="$$HOME/.local/bin:$$PATH" uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

install: ## Install dependencies
	@echo "📦 Installing dependencies..."
	PATH="$$HOME/.local/bin:$$PATH" uv sync

clean: ## Clean cache and temporary files
	@echo "🧹 Cleaning cache..."
	PATH="$$HOME/.local/bin:$$PATH" uv cache clean
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -delete

test: ## Run tests
	@echo "🧪 Running tests..."
	PATH="$$HOME/.local/bin:$$PATH" uv run python test_cve.py

add: ## Add a new dependency (usage: make add PACKAGE=package_name)
	@if [ -z "$(PACKAGE)" ]; then echo "❌ Please specify PACKAGE=package_name"; exit 1; fi
	@echo "📦 Adding dependency: $(PACKAGE)"
	PATH="$$HOME/.local/bin:$$PATH" uv add $(PACKAGE)
