"""GitHub Copilot Agent for dependency admission control and code review.
# tested-by: tests/unit/test_agent_main.py

Reactive PR flow: triggers on lockfile/manifest changes, evaluates packages via
the admission pipeline, runs Semgrep on changed files, and posts per-package
review comments with task-fit reasoning.
"""
