#!/usr/bin/env bash
set -euo pipefail

# Snapshot Semgrep rules from the registry at a pinned commit.
# Run this to update the pinned rules. The Dockerfile copies
# the snapshot into the container image.
#
# Usage: bash scripts/snapshot-semgrep-rules.sh

RULES_DIR="policies/semgrep/pinned"
SEMGREP_RULES_REPO="https://github.com/semgrep/semgrep-rules.git"
SEMGREP_RULES_COMMIT="v1.95.0"

echo "Snapshotting semgrep-rules at ${SEMGREP_RULES_COMMIT}..."

rm -rf "$RULES_DIR/community"
mkdir -p "$RULES_DIR/community"

git clone --depth=1 --branch "$SEMGREP_RULES_COMMIT" "$SEMGREP_RULES_REPO" "$RULES_DIR/community" 2>&1 | tail -2
rm -rf "$RULES_DIR/community/.git"

echo "Pinned version: $SEMGREP_RULES_COMMIT" > "$RULES_DIR/VERSION"
echo "Pinned at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RULES_DIR/VERSION"

rule_count=$(find "$RULES_DIR/community" -name "*.yaml" -o -name "*.yml" | wc -l | tr -d ' ')
echo "Snapshot complete: ${rule_count} rule files at ${SEMGREP_RULES_COMMIT}"
echo "Location: ${RULES_DIR}/community/"
