.PHONY: install dev test lint format typecheck build clean run help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

test: ## Run tests
	pytest tests/ -v

test-cov: ## Run tests with coverage
	pytest tests/ -v --cov=spectre --cov-report=html --cov-report=term

lint: ## Run ruff linter
	ruff check spectre/
	ruff format --check spectre/

format: ## Format code with ruff
	ruff format spectre/
	ruff check --fix spectre/

typecheck: ## Run mypy type checking
	mypy spectre/

build: ## Build distribution
	python -m build

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache htmlcov coverage.xml

run: ## Run spectre CLI
	python -m spectre

pre-commit: ## Install pre-commit hooks
	pre-commit install

scan: ## Example: make scan TARGET=https://example.com
	python -m spectre scan $(TARGET) --full
