# Quality Plugins

These plugins are **advisory** — they never block a merge. They surface signals that help reviewers make informed decisions.

---

## blast-radius

Counts how many symbols depend on a given function, surfacing the change surface before a reviewer has to guess.

| Severity | Condition |
|----------|-----------|
| Critical | 20+ dependents |
| High | 10–19 dependents |
| Info | < 10 dependents |

> Note: test fixtures routinely have high blast radius — that is healthy coupling, not a smell.

Even advisory, this tells a reviewer whether a one-line change touches 2 callers or 40.

---

## complexity

Measures cyclomatic complexity and maintainability index, grading each unit A–F.

| Severity | Condition |
|----------|-----------|
| Warning | Grade C — consider refactoring |
| High | Grade D — refactor recommended |
| Critical | Grade F — significant complexity debt |

Grade C or below is a prompt to simplify, not a hard stop.

Complexity debt compounds silently; surfacing it early costs nothing and saves the next engineer from a maze.

---

## cpd

Detects copy-paste duplication — the same logic repeated across multiple locations.

| Severity | Condition |
|----------|-----------|
| High | 20+ duplicated lines across 3+ sites |
| Warning | 10–19 duplicated lines |

Duplicate code is a quality signal: it is unlikely to pass a thorough human review, and advisory flagging makes that conversation easier to start.

---

## cspell

Spell-checks identifiers and comments throughout the codebase.

| Severity | Condition |
|----------|-----------|
| Warning | Misspelled identifier or symbol name |
| Info | Typo in a comment |

Misspelled names are harder to grep, autocomplete, and explain in code review — a small fix with compounding payoff.

---

## ls-lint

Enforces file and directory naming conventions across the project tree.

| Severity | Condition |
|----------|-----------|
| Warning | File or directory name does not match the configured pattern |

Consistent naming makes navigation predictable and removes the cognitive load of guessing whether a file is `UserService`, `user-service`, or `user_service`.
