PY ?= python
PORT ?= 5000

.PHONY: help install run web cli sample test test-web test-cli lint types clean

help:
	@echo "Docker Hardening Checker"
	@echo ""
	@echo "  make install     install runtime + dev dependencies"
	@echo "  make web         run the web UI on http://127.0.0.1:$(PORT)"
	@echo "  make cli         scan the repo with the CLI (text output)"
	@echo "  make sample      scan samples/ with the CLI"
	@echo "  make test        run the full pytest suite (with coverage)"
	@echo "  make lint        run ruff linter"
	@echo "  make types       run mypy type checker"
	@echo "  make clean       remove caches and temp files"

install:
	$(PY) -m pip install -e ".[dev]"

web:
	$(PY) app.py

cli:
	$(PY) cli.py .

sample:
	$(PY) cli.py samples

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .

types:
	$(PY) -m mypy app.py cli.py

clean:
	@find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache -o -name htmlcov \) -exec rm -rf {} + 2>/dev/null || true
	@rm -f .coverage coverage.xml hardening.sarif hardening.json _test_summary.md _test.sarif _live_test.df
