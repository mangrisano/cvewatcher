SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help dev start install clean test

help: ## Mostra questo messaggio di aiuto
	@echo "Comandi disponibili:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

dev: ## Avvia il server in modalità development con reload automatico
	@echo "🚀 Avvio server FastAPI in modalità development..."
	PATH="$$HOME/.local/bin:$$PATH" uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

start: ## Avvia il server in modalità produzione
	@echo "🚀 Avvio server FastAPI in modalità produzione..."
	PATH="$$HOME/.local/bin:$$PATH" uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

install: ## Installa le dipendenze
	@echo "📦 Installazione dipendenze..."
	PATH="$$HOME/.local/bin:$$PATH" uv sync

clean: ## Pulisce la cache e i file temporanei
	@echo "🧹 Pulizia cache..."
	PATH="$$HOME/.local/bin:$$PATH" uv cache clean
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -delete

test: ## Esegue i test (quando li aggiungerai)
	@echo "🧪 Esecuzione test..."
	PATH="$$HOME/.local/bin:$$PATH" uv run pytest

add: ## Aggiunge una nuova dipendenza (uso: make add PACKAGE=nome_pacchetto)
	@if [ -z "$(PACKAGE)" ]; then echo "❌ Specificare PACKAGE=nome_pacchetto"; exit 1; fi
	@echo "📦 Aggiunta dipendenza: $(PACKAGE)"
	PATH="$$HOME/.local/bin:$$PATH" uv add $(PACKAGE)
