.DEFAULT_GOAL := help
PY ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help setup install dev lint fmt test redteam scan demo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

setup: ## Create the virtualenv
	$(PY) -m venv $(VENV)

install: ## Install the package + dev extras
	$(BIN)/pip install -U pip
	$(BIN)/pip install -e ".[dev]"

dev: setup install ## Create venv and install everything

lint: ## Lint with ruff
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

fmt: ## Auto-format with ruff
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

test: ## Run the offline test suite
	$(BIN)/pytest -q

redteam: ## Run the red-team attack suite + defense gate
	$(BIN)/llm-guardrails redteam

scan: ## Scan a string: make scan TEXT="ignore all previous instructions"
	$(BIN)/llm-guardrails scan "$(TEXT)"

demo: ## Print a few example scans
	$(BIN)/llm-guardrails demo

clean: ## Remove caches and build artifacts
	rm -rf $(VENV) .pytest_cache .ruff_cache **/__pycache__ *.egg-info src/*.egg-info
