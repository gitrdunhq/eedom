# OPA Admission Policy — Input Schema

The `admission` package expects a single JSON input object with three top-level keys:
`findings`, `package`, and `config`.

## `input.findings` — array of scanner findings

Each element represents a single finding from a security scanner.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | yes | One of `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` |
| `category` | string | yes | Finding type: `"vulnerability"`, `"license"`, `"malware"` |
| `description` | string | yes | Human-readable description of the finding |
| `package_name` | string | yes | Name of the affected package |
| `version` | string | yes | Version of the affected package |
| `advisory_id` | string | yes | Advisory identifier (e.g. `CVE-2024-1234`, `MAL-2024-5678`) |
| `source_tool` | string | yes | Scanner that produced this finding (e.g. `osv-scanner`, `trivy`) |
| `license_id` | string | conditional | SPDX license identifier. Required when `category` is `"license"` |

## `input.package` — metadata about the package under evaluation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Package name |
| `version` | string | yes | Package version |
| `ecosystem` | string | yes | Package ecosystem (e.g. `pypi`, `npm`) |
| `scope` | string | yes | Dependency scope: `"runtime"` or `"dev"` |
| `environment_sensitivity` | string | yes | Deployment context (e.g. `"internet-facing"`, `"internal"`) |
| `first_published_date` | string (RFC 3339) | yes | When the package was first published. Used by the package-age rule |
| `transitive_dep_count` | integer | yes | Number of transitive dependencies this package pulls in |

## `input.config` — policy configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `forbidden_licenses` | array of string | `[]` | SPDX license IDs that are not allowed |
| `max_transitive_deps` | integer | `200` | Maximum transitive dependency count before a warning fires |
| `min_package_age_days` | integer | `90` | Minimum age in days a package must have been published |
| `rules_enabled` | object | (all true) | Per-rule toggle; see below |

### `input.config.rules_enabled`

Each key toggles a specific policy rule. Set to `false` to disable.

| Key | Controls | Default |
|-----|----------|---------|
| `critical_vuln` | Critical/high deny + medium warn for vulnerabilities | `true` |
| `forbidden_license` | Forbidden license deny | `true` |
| `package_age` | Package age deny | `true` |
| `malicious_package` | MAL- prefix advisory deny | `true` |
| `transitive_count` | Transitive dependency count warn | `true` |

## Output Shape

The policy produces three fields:

| Field | Type | Description |
|-------|------|-------------|
| `deny` | set of string | Denial messages. Non-empty means the package is rejected |
| `warn` | set of string | Warning messages. Non-empty (with empty deny) means approve with constraints |
| `decision` | string | `"reject"` if deny is non-empty, `"approve_with_constraints"` if only warn is non-empty, `"approve"` otherwise |
