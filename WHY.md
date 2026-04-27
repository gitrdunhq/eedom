# Eagle Eyed Dom

<img src="/Users/samfakhreddine/repos/eedom/assets/hero.webp" alt="hero" style="zoom:33%;" />

Eagle Eyed Dom (eedom) is a fully deterministic dependency and code review engine for CI — it does the mechanical half of every PR review so engineers can focus on the half that requires judgment. Every PR that touches a dependency manifest or source file triggers the same tedious checklist: known CVEs, license compatibility, package age, leaked secrets, copy-paste duplication, cyclomatic complexity — eedom runs all of it in under ten minutes, without a human. 

The pipeline detects changed packages across 36 ecosystems, fans out across 36 specialist plugins in parallel (Syft, OSV-Scanner, Trivy, ScanCode, Semgrep, Gitleaks, ClamAV, and more), deduplicates overlapping findings by advisory ID with highest-severity-wins logic, then hands the normalized result set to an OPA policy engine that makes the accept/reject decision in pure Rego — no prompts, no probability, no "it depends on the model's mood today."

 What makes eedom different is the constraint it refuses to break: zero LLM in the decision path. The build passes or fails on deterministic rules that any engineer can read, audit, and debate — not on a language model's interpretation of those rules. 

It's also fail-open by design: every scanner runs in its own timeout envelope, every failure returns a typed `ScanResult` and the pipeline continues, so a missing binary or a PyPI timeout never silently blocks a deploy. 

Two entry points drive the same pipeline — a CLI for CI and a GitHub Copilot Agent (GATEKEEPER) for reactive PR review — and every run writes tamper-evident evidence sealed with a SHA-256 hash chain and appended to a Parquet audit lake queryable with DuckDB. Eedom is built for platform and security engineering teams that need a CI gate with a defensible audit trail, not a vibes-based review bot. 

Teams that adopt it reclaim the senior engineer time currently spent answering "is this dep safe?" on the fourth PR of the afternoon — and they get a chain of custody from PR diff to production container image via SLSA Level 3 attestation as a bonus.

---

## Architecture

```mermaid
graph LR
    %% Enlarged text configurations
    classDef interface fill:#2b3137,stroke:#24292e,stroke-width:3px,color:#fff,font-size:36px,font-weight:bold;
    classDef core fill:#0366d6,stroke:#005cc5,stroke-width:3px,color:#fff,font-size:36px,font-weight:bold;
    classDef plugin fill:#28a745,stroke:#36863a,stroke-width:3px,color:#fff,font-size:36px,font-weight:bold;
    classDef data fill:#dbab09,stroke:#b08800,stroke-width:3px,color:#000,font-size:36px,font-weight:bold;
    classDef output fill:#6f42c1,stroke:#5a32a3,stroke-width:3px,color:#fff,font-size:36px,font-weight:bold;

    subgraph Presentation["Presentation"]
        direction TB
        CLI(["CLI<br/>(evaluate / review)"]):::interface
        GATE(["GATEKEEPER<br/>(Copilot Agent)"]):::interface
    end

    subgraph Orchestration["Pipeline Orchestration"]
        direction TB
        PIPE{"Pipeline Controller"}:::core
        REG["PluginRegistry<br/>(auto-discovery<br/>& topo sort)"]:::core
    end

    subgraph Execution["Parallel Plugins"]
        direction TB
        DEP["Dependency<br/>(Syft, OSV,<br/>Trivy, ScanCode)"]:::plugin
        CODE["Code Analysis<br/>(Semgrep, CPD,<br/>Mypy)"]:::plugin
        INFRA["Infrastructure<br/>(kube-linter, cfn-nag)"]:::plugin
        QUALITY["Quality<br/>(Lizard, cspell,<br/>BlastRadius)"]:::plugin
        SUPPLY["Supply Chain<br/>(Gitleaks, ClamAV)"]:::plugin
    end

    subgraph Processing["Normalization & Decision"]
        direction TB
        NORM["Normalizer<br/>(dedup,<br/>max-severity)"]:::core
        ACT["Actionability Engine<br/>(fixable vs blocked)"]:::core
        OPA{"OPA Policy Engine<br/>(6 Rego rules)"}:::core
    end

    subgraph Outputs["Artifacts & Sealing"]
        direction TB
        REND["Renderer<br/>(Jinja2 PR comment)"]:::output
        SARIF["SARIF v2.1.0"]:::output
        SEAL["Evidence Sealer<br/>(SHA-256 chain)"]:::output
    end

    subgraph Storage["Data Persistence"]
        direction TB
        EVIDENCE[/"EvidenceStore"/]:::data
        PARQUET[/"Parquet Audit Log<br/>(DuckDB)"/]:::data
        DB[("PostgreSQL")]:::data
    end

    %% Routing
    CLI --> PIPE
    GATE --> PIPE
    
    PIPE --> REG
    REG --> DEP & CODE & INFRA & QUALITY & SUPPLY
    
    DEP & CODE & INFRA & QUALITY & SUPPLY --> NORM
    
    NORM --> ACT
    ACT --> OPA
    
    OPA --> REND & SARIF
    OPA --> SEAL
    OPA -.-> DB
    
    SEAL --> EVIDENCE
    SEAL --> PARQUET
```

