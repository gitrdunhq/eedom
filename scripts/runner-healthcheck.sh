#!/bin/bash
# Runner health check — restart if dead
# Install: crontab -e → */5 * * * * /path/to/runner-healthcheck.sh

RUNNER_DIR="$HOME/actions-runner"
LOG="$RUNNER_DIR/healthcheck.log"

if ! pgrep -f "actions-runner/bin/Runner.Listener" > /dev/null 2>&1; then
    echo "$(date): Runner dead — restarting" >> "$LOG"
    cd "$RUNNER_DIR" && nohup ./run.sh >> "$LOG" 2>&1 &
else
    # Check if it's actually processing (last job > 30 min ago = suspicious)
    LAST_JOB=$(tail -1 "$RUNNER_DIR/runner.log" 2>/dev/null | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "")
    if [ -n "$LAST_JOB" ]; then
        echo "$(date): Runner alive, last activity: $LAST_JOB" >> "$LOG"
    fi
fi
