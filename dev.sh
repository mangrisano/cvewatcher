#!/bin/bash

# Script per avviare FastAPI con uv
export PATH="$HOME/.local/bin:$PATH"

echo "🚀 Avvio CVE Watcher in modalità development..."
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
