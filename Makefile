PYTHON ?= python3.12
VENV   ?= .venv

.PHONY: install test demo clean help

help:
	@echo "Afterlife — make targets"
	@echo ""
	@echo "  install   create $(VENV)/ and install with dev extras"
	@echo "  test      run the pytest suite"
	@echo "  demo      run the self-contained synthetic demo"
	@echo "  clean     remove venv, caches, and the local DB"
	@echo ""
	@echo "Override the Python interpreter with: make PYTHON=python3.13 install"

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"

test:
	$(VENV)/bin/pytest

demo:
	$(VENV)/bin/python demo/run.py

clean:
	rm -rf $(VENV) afterlife.db .pytest_cache .ruff_cache .mypy_cache
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.egg-info" -type d -exec rm -rf {} +
