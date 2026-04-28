#!/usr/bin/env python3
"""token-stats.py — Per-file token estimates for the eedom codebase.

Usage: uv run python3 scripts/token-stats.py
"""

from __future__ import annotations

import re
import statistics
from pathlib import Path


def estimate_tokens(text: str) -> int:
    words = len(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text))
    symbols = len(re.findall(r"[^a-zA-Z0-9_\s]", text))
    return int(words * 1.3 + symbols * 0.7)


def report_section(label: str, root: str) -> list[tuple[str, int, int]]:
    files = sorted(Path(root).rglob("*.py"))
    data = []
    for f in files:
        text = f.read_text()
        data.append((str(f), len(text.splitlines()), estimate_tokens(text)))

    tok_total = sum(t for _, _, t in data)
    print(f"\n  ── {label} ({len(data)} files, {tok_total:,} tokens) ──")
    print(f"  {'File':<55} {'Lines':>5} {'Tokens':>6}")
    print(f"  {'─' * 55} {'─' * 5} {'─' * 6}")
    for name, lines, tokens in sorted(data, key=lambda x: -x[2]):
        short = str(Path(name).relative_to(root.split("/")[0]))
        if len(short) > 54:
            short = "..." + short[-51:]
        print(f"  {short:<55} {lines:>5} {tokens:>6,}")
    return data


def main() -> None:
    print("\n  eedom Per-File Token Report")
    print("  ===========================")

    src = report_section("SOURCE", "src/eedom")
    tests = report_section("TESTS", "tests")

    src_tok = [t for _, _, t in src]
    test_tok = [t for _, _, t in tests]

    print(f"\n  {'─' * 68}")
    print(f"  {'Metric':<12} {'Source':>10} {'Tests':>10} {'Total':>10}")
    print(f"  {'─' * 12} {'─' * 10} {'─' * 10} {'─' * 10}")
    print(f"  {'Files':<12} {len(src):>10} {len(tests):>10} {len(src) + len(tests):>10}")
    print(
        f"  {'Tokens':<12} {sum(src_tok):>10,} {sum(test_tok):>10,} {sum(src_tok) + sum(test_tok):>10,}"
    )
    print(
        f"  {'Avg/file':<12} {statistics.mean(src_tok):>10,.0f} {statistics.mean(test_tok):>10,.0f}"
    )
    print(
        f"  {'Median/file':<12} {statistics.median(src_tok):>10,.0f} {statistics.median(test_tok):>10,.0f}"
    )
    print(f"  {'Ratio':<12} {'':>10} {'':>10} {sum(test_tok) / sum(src_tok):>9.2f}:1")
    print()


if __name__ == "__main__":
    main()
