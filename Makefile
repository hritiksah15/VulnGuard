.PHONY: help install run dev seed reseed reset-db import-cve import-kev download-dataset test lint clean

PYTHON  = venv/bin/python
PIP     = venv/bin/pip
FLASK   = cd backend && PYTHONPATH=. ../venv/bin/python -m flask
BACKEND = cd backend && PYTHONPATH=.

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Environment ──────────────────────────────────────────────

venv: ## Create virtual environment
	python3 -m venv venv

install: venv ## Install all dependencies
	$(PIP) install -r backend/requirements.txt

# ── Running ──────────────────────────────────────────────────

run: ## Start development server (port 5000)
	$(BACKEND) ../$(PYTHON) run.py

dev: ## Start development server with auto-reload
	$(BACKEND) ../$(PYTHON) run.py --port 5000

prod: ## Start with gunicorn (4 workers)
	$(BACKEND) ../venv/bin/gunicorn "app:create_app()" -b 0.0.0.0:5000 -w 4

# ── Database ─────────────────────────────────────────────────

seed: ## Seed database with sample data (3 users + 109 vulns)
	$(BACKEND) ../$(PYTHON) -m seeds.seed_data

reseed: ## Drop DB then seed from scratch (use after Postman tests)
	$(BACKEND) ../$(PYTHON) -m seeds.seed_data --reseed

reset-db: ## Drop the entire database (no seeding)
	$(BACKEND) ../$(PYTHON) -m seeds.seed_data --reset

import-cve: ## Import synthetic/NVD CVE data (200 entries)
	$(BACKEND) ../$(PYTHON) -m scripts.import_cve_data

import-kev: ## Import CISA KEV catalog into VulnGuard
	$(BACKEND) ../$(PYTHON) -m scripts.import_kev_data

import-kev-limited: ## Import first 500 KEV entries
	$(BACKEND) ../$(PYTHON) -m scripts.import_kev_data --limit 500

download-dataset: ## Download CISA KEV catalog & NVD data
	$(BACKEND) ../$(PYTHON) -m scripts.download_dataset

setup-db: seed import-cve import-kev ## Full database setup (seed + CVE + KEV)

# ── Testing ──────────────────────────────────────────────────

test: ## Run health check & quick smoke test
	@echo "🩺 Health check..."
	@curl -sf http://localhost:5000/api/v1/health | python3 -m json.tool
	@echo "\n✅ API is running"

test-login: ## Test login endpoint
	@curl -sf -X POST http://localhost:5000/api/v1/auth/login \
		-H "Content-Type: application/json" \
		-d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}' \
		| python3 -m json.tool

# ── Maintenance ──────────────────────────────────────────────

clean: ## Remove Python cache files and logs
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf backend/logs/*.log 2>/dev/null || true

clean-all: clean ## Clean + remove venv
	rm -rf venv
