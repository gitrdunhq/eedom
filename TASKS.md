# TASKS — next branch

Epic: #146 — Black-Box Architecture Refactoring
Branch: `next` (main frozen at v0.2.7)
Principles: Eskil Steenberg — black box modules, primitives first, vendor insulation

## Dependency Graph

```
P0 (source cleanup) ─┐
                      ├─> P1 (PluginFinding) ─┐
                      │                        ├─> P2 (policy separation) ─┐
                      │                        │                           ├─> P3 (composition root) ─┐
                      │                        │                           │                           ├─> P8 (thin entrypoints)
                      │                        │                           │                           ├─> P9 (audit/persistence)
                      │                        │                           │                           └─> P10 (drift guards)
                      │                        ├─> P7 (renderer boundary)  │
                      │                        │                           │
                      ├─> P4 (ToolRunnerPort) ─┘                           │
                      │                                                    │
                      ├─> P5 (RepoSnapshotPort) ──────────────────────────┘
                      │
                      └─> P6 (PullRequestPublisherPort) ──────────────────┘
```

## Packet 0: Source of Truth Cleanup

| # | Task | Size | Status |
|---|------|------|--------|
| #147 | Inventory duplicate src/* mirror trees | S | TODO |
| #148 | Remove duplicate src/* mirror trees | S | TODO |
| #149 | CI guard preventing mirror reintroduction | S | TODO |

## Packet 1: PluginFinding Contract Shim

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #150 | Define PluginFinding and FindingLocation dataclasses | P0 | S | TODO |
| #151 | Add finding normalizer at registry boundary | #150 | M | TODO |
| #152 | Migrate SARIF converter to consume PluginFinding | #151 | S | TODO |
| #153 | Migrate renderer to consume PluginFinding | #151 | S | TODO |
| #154 | Migrate json_report to consume PluginFinding | #151 | S | TODO |
| #155 | Migrate actionability classifier to consume PluginFinding | #151 | S | TODO |

## Packet 2: Separate Analyzer and Policy Contracts

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #156 | Define PolicyEnginePort and PolicyInput/PolicyDecision | P1 | M | TODO |
| #157 | Implement OPA adapter behind PolicyEnginePort | #156 | M | TODO |
| #158 | Remove depends_on=[*] convention from registry | #157 | M | TODO |

## Packet 3: Bootstrap Composition Root

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #159 | Define port protocols for scanner registry, policy, storage | P2 | M | TODO |
| #160 | Create bootstrap composition function | #159 | M | TODO |
| #161 | Wire CLI and agent through composition root | #160 | M | TODO |

## Packet 4: ToolRunnerPort and Subprocess Unification

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #162 | Define ToolInvocation, ToolResult, and ToolRunnerPort | P0 | S | TODO |
| #163 | Implement subprocess ToolRunner adapter | #162 | S | TODO |
| #164 | Route OPA and 2 scanner plugins through ToolRunnerPort | #163 | M | TODO |

## Packet 5: Immutable RepoSnapshotPort

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #165 | Define RepoSnapshotPort and implement git worktree adapter | P0 | M | TODO |

## Packet 6: PullRequestPublisherPort

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #166 | Define PullRequestPublisherPort | P0 | S | TODO |
| #167 | Implement GitHub adapter and route CLI/agent through it | #166 | M | TODO |

## Packet 7: Renderer Boundary

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #168 | Define ReviewReport model and ReportRendererPort | P1 | M | TODO |
| #169 | Migrate markdown, SARIF, JSON renderers behind port | #168 | L | TODO |

## Packet 8: Thin Entrypoints

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #170 | Extract use case layer from CLI review command | P3 | L | TODO |
| #171 | Align agent and webhook with same use case layer | #170 | M | TODO |

## Packet 9: Audit and Persistence Contract

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #172 | Define DecisionStore, EvidenceStore, AuditSink ports | P3 | M | TODO |
| #173 | Implement adapters and wire through composition root | #172 | M | TODO |

## Packet 10: Contract-Generated Docs and Drift Guards

| # | Task | Depends | Size | Status |
|---|------|---------|------|--------|
| #174 | Contract-generated docs and drift guards | P3 | M | TODO |

## Totals

- **28 tasks** across 11 packets
- **S:** 10 tasks, **M:** 15 tasks, **L:** 3 tasks
- **Critical path:** P0 → P1 → P2 → P3 → P8/P9/P10
- **Parallel lanes after P0:** P4, P5, P6 can run alongside P1
