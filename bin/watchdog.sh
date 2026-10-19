#!/bin/bash
# ==============================================================================
# bin/watchdog.sh - MikroTik Mesh Daemon Watchdog
# Ensures the persistent 24/7 background service remains active
#
# Add to crontab (every 5 or 10 minutes):
# */5 * * * * bash /path/to/bin/watchdog.sh >/dev/null 2>&1
# ==============================================================================

MKT_BIN="/home/u560021660/bin/mkt-cli"
PID_FILE="/tmp/mkt_mesh_daemon.pid"
LOG_FILE="/tmp/mkt_mesh_daemon.log"
CONTROL_BIND="127.0.0.1:20560"
RELAY_BIND="0.0.0.0:443"

# 1. Verify executable presence
if [ ! -f "$MKT_BIN" ]; then
    MKT_BIN="$(dirname "$0")/../target/release/mkt-cli"
    if [ ! -f "$MKT_BIN" ]; then
        exit 0
    fi
fi

# 2. Check if process is running
RUNNING=0
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE" 2>/dev/null | tr -d ' ')
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        RUNNING=1
    fi
fi

# Fallback check via pgrep
if [ $RUNNING -eq 0 ]; then
    if pgrep -f "mkt-cli daemon" >/dev/null 2>&1; then
        RUNNING=1
    fi
fi

# 3. If inactive, restart immediately in background with nohup
if [ $RUNNING -eq 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WATCHDOG] Daemon mkt-cli inactive. Restarting in background..." >> "$LOG_FILE"
    nohup "$MKT_BIN" daemon --control "$CONTROL_BIND" --relay "$RELAY_BIND" >> "$LOG_FILE" 2>&1 &
    NEW_PID=$!
    echo $NEW_PID > "$PID_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WATCHDOG] Daemon reactivated with PID $NEW_PID." >> "$LOG_FILE"
fi
