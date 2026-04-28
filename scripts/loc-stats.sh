#!/usr/bin/env bash
# loc-stats.sh — Lines of code and file statistics for the eedom codebase.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

count_dir() {
    local dir="$1" label="$2"
    local files lines avg median p25 p75 min max
    files=$(find "$REPO_ROOT/$dir" -name '*.py' 2>/dev/null | wc -l | tr -d ' ')
    if [ "$files" -eq 0 ]; then
        printf "%-24s %6s %8s %6s %6s %6s %6s %6s\n" "$label" "0" "0" "-" "-" "-" "-" "-"
        return
    fi
    local stats
    stats=$(find "$REPO_ROOT/$dir" -name '*.py' -exec wc -l {} + | grep -v total | awk '{print $1}' | sort -n)
    lines=$(echo "$stats" | awk '{s+=$1} END {print s}')
    min=$(echo "$stats" | head -1)
    max=$(echo "$stats" | tail -1)
    local n
    n=$(echo "$stats" | wc -l | tr -d ' ')
    avg=$((lines / n))
    p25=$(echo "$stats" | awk "NR==int($n*0.25){print}")
    median=$(echo "$stats" | awk "NR==int($n*0.5){print}")
    p75=$(echo "$stats" | awk "NR==int($n*0.75){print}")
    printf "%-24s %6d %8d %6d %6d %6d %6d %6d\n" "$label" "$files" "$lines" "$median" "$avg" "$p25" "$p75" "$max"
}

printf "\n  eedom Codebase Statistics\n"
printf "  ========================\n\n"
printf "%-24s %6s %8s %6s %6s %6s %6s %6s\n" "Directory" "Files" "Lines" "Median" "Avg" "P25" "P75" "Max"
printf "%-24s %6s %8s %6s %6s %6s %6s %6s\n" "─────────" "─────" "─────" "──────" "───" "───" "───" "───"

count_dir "src/eedom/cli"        "  cli/"
count_dir "src/eedom/core"       "  core/"
count_dir "src/eedom/data"       "  data/"
count_dir "src/eedom/plugins"    "  plugins/"
count_dir "src/eedom/agent"      "  agent/"
count_dir "src/eedom"            "src/eedom/ (total)"

printf "%-24s %6s %8s %6s %6s %6s %6s %6s\n" "─────────" "─────" "─────" "──────" "───" "───" "───" "───"

count_dir "tests/unit"           "  unit/"
count_dir "tests/integration"    "  integration/"
count_dir "tests"                "tests/ (total)"

printf "%-24s %6s %8s %6s %6s %6s %6s %6s\n" "─────────" "─────" "─────" "──────" "───" "───" "───" "───"

total_src=$(find "$REPO_ROOT/src" -name '*.py' -exec wc -l {} + | grep total | awk '{print $1}')
total_test=$(find "$REPO_ROOT/tests" -name '*.py' -exec wc -l {} + | grep total | awk '{print $1}')
total=$((total_src + total_test))
ratio=$(awk "BEGIN {printf \"%.2f\", $total_test / $total_src}")

printf "\n  Total: %d lines across %d files\n" "$total" "$(find "$REPO_ROOT/src" "$REPO_ROOT/tests" -name '*.py' | wc -l | tr -d ' ')"
printf "  Test:Code ratio: %s:1\n\n" "$ratio"

over500=$(find "$REPO_ROOT/src" -name '*.py' -exec wc -l {} + | grep -v total | awk '$1 > 500 {print "    " $1 " " $2}')
if [ -n "$over500" ]; then
    printf "  ⚠ Files over 500-line cap:\n%s\n\n" "$over500"
fi
