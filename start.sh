#!/usr/bin/env bash
# SecureAudit AI: one-command dashboard for macOS / Linux.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

echo "Installing / updating SecureAudit AI..."
.venv/bin/pip install -q -e .

PORT="${SECUREAUDIT_PORT:-8750}"
echo "Dashboard: http://127.0.0.1:${PORT}  (Ctrl+C to stop)"
( sleep 2 && (open "http://127.0.0.1:${PORT}" 2>/dev/null || xdg-open "http://127.0.0.1:${PORT}" 2>/dev/null || true) ) &
exec .venv/bin/python -m uvicorn secureaudit.webapp:app --host 127.0.0.1 --port "$PORT"
