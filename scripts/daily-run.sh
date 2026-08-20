#!/bin/bash
# Daily ingest + digest, invoked by launchd (see install-launchd.sh).
#
# Deliberately does NOT use `set -e`: a partial ingest is still worth digesting,
# and `lomst actions` exits 2 by design when something needs immediate attention.
# Bailing on the first non-zero status would throw away the run's output.
set -uo pipefail

LOMST_HOME="${LOMST_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export LOMST_HOME

PY="${LOMST_PYTHON:-$LOMST_HOME/.venv/bin/python}"
LOG_DIR="$LOMST_HOME/var/logs"
STAMP="$(date -u +%Y-%m-%d)"
LOG="$LOG_DIR/$STAMP.log"

mkdir -p "$LOG_DIR"

if [[ ! -x "$PY" ]]; then
  echo "error: interpreter not found at $PY" >&2
  echo "create it with: python3 -m venv .venv && .venv/bin/pip install -e ." >&2
  exit 78  # EX_CONFIG
fi

{
  echo "===================================================================="
  echo "lomst daily run  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "===================================================================="

  echo
  echo "--- ingest ---"
  "$PY" -m lomst ingest
  ingest_status=$?
  echo "ingest exit: $ingest_status"

  echo
  echo "--- digest ---"
  "$PY" -m lomst digest

  echo
  echo "--- immediate actions ---"
  "$PY" -m lomst actions --urgency immediate
  actions_status=$?

  echo
  echo "run complete: ingest=$ingest_status actions=$actions_status"
} >>"$LOG" 2>&1

# Keep 90 days of run logs; the SQLite store and git history are the durable record.
find "$LOG_DIR" -name '*.log' -type f -mtime +90 -delete 2>/dev/null

# Surface immediate governance actions to the desktop. Section 11.4 expects a
# critical advisory on an approved runtime to prompt an assessment, not to sit in
# a log file until someone looks.
if "$PY" -m lomst actions --urgency immediate --json 2>/dev/null | grep -q '"urgency"'; then
  count=$("$PY" -m lomst actions --urgency immediate --json 2>/dev/null \
          | grep -c '"urgency"')
  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$count immediate governance action(s). See lomst actions.\" with title \"Model Security Tracker\"" >/dev/null 2>&1
  fi
fi

exit 0
