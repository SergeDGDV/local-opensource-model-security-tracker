#!/bin/bash
# Install (or remove) the launchd agent that runs the tracker daily.
#
#   ./scripts/install-launchd.sh            install, runs 08:15 local time
#   ./scripts/install-launchd.sh --hour 7   install at 07:15
#   ./scripts/install-launchd.sh --uninstall
#   ./scripts/install-launchd.sh --status
#   ./scripts/install-launchd.sh --verify     run it now and confirm it worked
set -euo pipefail

LABEL="com.paradoxinteractive.lomst.daily"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOUR=8
MINUTE=15
ACTION=install

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hour) HOUR="$2"; shift 2 ;;
    --minute) MINUTE="$2"; shift 2 ;;
    --uninstall) ACTION=uninstall; shift ;;
    --status) ACTION=status; shift ;;
    --verify) ACTION=verify; shift ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

case "$ACTION" in
  status)
    if launchctl list | grep -q "$LABEL"; then
      echo "loaded:"
      launchctl list "$LABEL" | sed 's/^/  /'
    else
      echo "not loaded"
    fi
    [[ -f "$PLIST" ]] && echo "plist: $PLIST" || echo "plist: absent"
    exit 0
    ;;
  uninstall)
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "removed $LABEL"
    exit 0
    ;;
  verify)
    # Actually run the job and confirm it produced output. `launchctl list`
    # reporting the agent as loaded says nothing about whether it can run.
    if ! launchctl list | grep -q "$LABEL"; then
      echo "not installed; run $0 first" >&2
      exit 1
    fi
    ERR="$ROOT/var/logs/launchd.err.log"
    TODAY_LOG="$ROOT/var/logs/$(date -u +%Y-%m-%d).log"
    : >"$ERR" 2>/dev/null || true
    before=$( { wc -c <"$TODAY_LOG"; } 2>/dev/null || echo 0 )
    launchctl kickstart -p "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      after=$( { wc -c <"$TODAY_LOG"; } 2>/dev/null || echo 0 )
      [[ "$after" -gt "$before" ]] && break
      [[ -s "$ERR" ]] && break
      sleep 3
    done
    if [[ -s "$ERR" ]]; then
      echo "FAILED - the agent is loaded but could not run:"
      sed 's/^/  /' "$ERR"
      echo
      echo "If this says 'Operation not permitted', the repo is in a"
      echo "privacy-protected folder. See: $0 --help"
      exit 1
    fi
    after=$( { wc -c <"$TODAY_LOG"; } 2>/dev/null || echo 0 )
    if [[ "$after" -gt "$before" ]]; then
      echo "OK - job ran and wrote to $TODAY_LOG"
      exit 0
    fi
    echo "INCONCLUSIVE - no new log output and no error after 90s" >&2
    exit 1
    ;;
esac

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "error: $ROOT/.venv/bin/python not found." >&2
  echo "run: python3 -m venv .venv && .venv/bin/pip install -e ." >&2
  exit 78
fi

# ---------------------------------------------------------------- TCC preflight
#
# macOS TCC blocks launchd agents from READING file contents under the protected
# user folders, even though they can stat paths there. A job installed from
# ~/Documents therefore fails with "Operation not permitted" every single time
# while looking perfectly healthy in `launchctl list`. Refusing to install is
# better than a scheduled job that silently never runs.
TCC_PROTECTED=0
case "$ROOT/" in
  "$HOME/Documents/"*|"$HOME/Desktop/"*|"$HOME/Downloads/"*|"$HOME/Library/Mobile Documents/"*)
    TCC_PROTECTED=1 ;;
esac

if [[ "$TCC_PROTECTED" == "1" && "${LOMST_FORCE_INSTALL:-}" != "1" ]]; then
  cat >&2 <<WARN
error: $ROOT
       is inside a macOS privacy-protected folder (Documents / Desktop /
       Downloads / iCloud Drive).

A launchd agent cannot read file contents there without Full Disk Access, so the
daily job would fail with "Operation not permitted" on every run. Verified
behaviour, not a guess: launchd can stat these paths but not read them.

Pick one:

  1. Move the repo somewhere unprotected (recommended):
         mv "$ROOT" ~/src/local-opensource-model-security-tracker
         cd ~/src/local-opensource-model-security-tracker
         rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -e .
         ./scripts/install-launchd.sh

  2. Grant Full Disk Access to /bin/bash in
         System Settings > Privacy & Security > Full Disk Access
     This is broad and affects every shell script on the machine. Not advised.

  3. Skip scheduling and run it yourself:
         lomst ingest && lomst digest && lomst actions

To install anyway (it will not run): LOMST_FORCE_INSTALL=1 $0
WARN
  exit 78
fi

chmod +x "$ROOT/scripts/daily-run.sh"
mkdir -p "$HOME/Library/LaunchAgents" "$ROOT/var/logs"

cat >"$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT/scripts/daily-run.sh</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>LOMST_HOME</key>
    <string>$ROOT</string>
  </dict>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>$HOUR</integer>
    <key>Minute</key><integer>$MINUTE</integer>
  </dict>

  <!-- Laptops sleep. Without this the run is skipped entirely on any day the
       machine was closed at the scheduled time, which for a daily tracker means
       silent gaps in coverage. -->
  <key>RunAtLoad</key>
  <false/>
  <key>StartOnMount</key>
  <false/>

  <key>StandardOutPath</key>
  <string>$ROOT/var/logs/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT/var/logs/launchd.err.log</string>

  <key>ProcessType</key>
  <string>Background</string>
  <key>LowPriorityIO</key>
  <true/>
  <key>Nice</key>
  <integer>5</integer>
</dict>
</plist>
PLIST_EOF

plutil -lint "$PLIST" >/dev/null

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null \
  || launchctl load "$PLIST"

printf 'installed %s\n' "$LABEL"
printf '  schedule : daily at %02d:%02d local time\n' "$HOUR" "$MINUTE"
printf '  logs     : %s/var/logs/\n' "$ROOT"
printf '  run now  : launchctl kickstart -p gui/%s/%s\n' "$(id -u)" "$LABEL"
printf '  remove   : %s --uninstall\n' "$0"
echo
echo 'Note: launchd skips StartCalendarInterval runs while the machine is asleep.'
echo 'If the Mac is routinely closed at that hour, pick a time it is usually awake.'
