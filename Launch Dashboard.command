#!/bin/bash
# Double-click this file to open the Model Security Tracker in your browser.
#
# It sets itself up on first run, so a colleague with no development tools
# beyond Python can use it. Close the Terminal window (or press Ctrl+C) to stop.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

PORT="${LOMST_PORT:-8765}"

printf '\n  Model Security Tracker\n'
printf '  ----------------------\n\n'

# --- first-run setup --------------------------------------------------------
if [[ ! -x ".venv/bin/lomst" ]]; then
  echo "  First run: setting up. This takes a minute or two..."
  PY=""
  for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
  done
  if [[ -z "$PY" ]]; then
    echo
    echo "  Python 3 is not installed."
    echo "  Install it from https://www.python.org/downloads/ and run this again."
    echo
    read -r -p "  Press Return to close." _
    exit 78
  fi
  "$PY" -m venv .venv || { echo "  Could not create the environment."; read -r _; exit 1; }
  ./.venv/bin/pip install --quiet --upgrade pip
  ./.venv/bin/pip install --quiet -e . || { echo "  Setup failed."; read -r _; exit 1; }
  echo "  Setup complete."
  echo
fi

# --- if it is already running, just open the browser ------------------------
if curl -sf -o /dev/null "http://127.0.0.1:$PORT/api/overview" 2>/dev/null; then
  echo "  Already running. Opening your browser..."
  open "http://127.0.0.1:$PORT/"
  echo
  read -r -p "  Press Return to close this window." _
  exit 0
fi

echo "  Opening http://127.0.0.1:$PORT/ in your browser."
echo "  Leave this window open while you use the dashboard."
echo "  To stop: close this window, or press Ctrl+C."
echo

exec ./.venv/bin/lomst serve --port "$PORT"
