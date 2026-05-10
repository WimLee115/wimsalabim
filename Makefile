# wimsalabim · developer Makefile
# Run `make help` for a summary.

.DEFAULT_GOAL := help

PYTHON      ?= python3
VENV        ?= .venv
VENV_BIN     = $(VENV)/bin
PIP          = $(VENV_BIN)/pip
PYTEST       = $(VENV_BIN)/pytest
RUFF         = $(VENV_BIN)/ruff
MYPY         = $(VENV_BIN)/mypy
BANDIT       = $(VENV_BIN)/bandit
PIPAUDIT     = $(VENV_BIN)/pip-audit
PRECOMMIT    = $(VENV_BIN)/pre-commit

.PHONY: help dev install reinstall fmt lint typecheck test test-cov audit security all clean build dist publish-test publish

help:
	@echo "wimsalabim · make targets"
	@echo ""
	@echo "  make dev           Create venv + install dev deps + pre-commit hooks"
	@echo "  make install       Install from source (editable) into existing env"
	@echo "  make reinstall     Wipe venv and dev-install from scratch"
	@echo ""
	@echo "  make fmt           Format with ruff"
	@echo "  make lint          ruff check + ruff format --check"
	@echo "  make typecheck     mypy --strict"
	@echo "  make test          pytest"
	@echo "  make test-cov      pytest with coverage report"
	@echo "  make security      bandit + pip-audit"
	@echo "  make audit         security + lint + typecheck (no tests)"
	@echo "  make all           lint + typecheck + test + security  (CI gates)"
	@echo ""
	@echo "  make build         Build wheel + sdist into ./dist"
	@echo "  make dist          Alias for 'build'"
	@echo "  make publish-test  Upload to TestPyPI (requires twine + creds)"
	@echo "  make publish       Upload to PyPI       (requires twine + creds)"
	@echo ""
	@echo "  make clean         Remove caches, build artifacts, venv"

# ── Setup ────────────────────────────────────────────────────────────────
$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

dev: $(VENV)/bin/activate
	$(PIP) install -e ".[dev]"
	$(PIP) install pre-commit
	$(PRECOMMIT) install || true
	@echo ""
	@echo "  Activate with:  source $(VENV)/bin/activate"

install:
	pip install -e ".[dev]"

reinstall: clean dev

# ── Quality ──────────────────────────────────────────────────────────────
fmt:
	$(RUFF) format src tests

lint:
	$(RUFF) format --check src tests
	$(RUFF) check src tests

typecheck:
	$(MYPY) src

test:
	$(PYTEST) -v

test-cov:
	$(PYTEST) --cov=wimsalabim --cov-report=term-missing --cov-report=html

security:
	$(BANDIT) -r src --severity-level low
	$(PIPAUDIT)

audit: lint typecheck security

all: lint typecheck test security
	@echo ""
	@echo "  All gates passed. Ready to ship."

# ── Build & publish ──────────────────────────────────────────────────────
build:
	$(PIP) install --upgrade build
	$(PYTHON) -m build

dist: build

publish-test: build
	$(PIP) install --upgrade twine
	$(VENV_BIN)/twine check dist/*
	$(VENV_BIN)/twine upload --repository testpypi dist/*

publish: build
	$(PIP) install --upgrade twine
	$(VENV_BIN)/twine check dist/*
	$(VENV_BIN)/twine upload dist/*

# ── Housekeeping ─────────────────────────────────────────────────────────
clean:
	rm -rf $(VENV) build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
