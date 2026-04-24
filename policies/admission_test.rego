package admission_test

import rego.v1

import data.admission

# --- Helper: base input with no findings and all rules enabled ---

base_config := {
	"forbidden_licenses": ["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0"],
	"max_transitive_deps": 200,
	"min_package_age_days": 90,
	"rules_enabled": {
		"critical_vuln": true,
		"forbidden_license": true,
		"package_age": true,
		"malicious_package": true,
		"transitive_count": true,
	},
}

base_package := {
	"name": "example-lib",
	"version": "1.0.0",
	"ecosystem": "pypi",
	"scope": "runtime",
	"environment_sensitivity": "internet-facing",
	"first_published_date": "2020-01-01T00:00:00Z",
	"transitive_dep_count": 42,
}

clean_input := {
	"findings": [],
	"pkg": base_package,
	"config": base_config,
}

# --- T-010: Critical vulnerability triggers deny ---

test_critical_vuln_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "critical",
		"category": "vulnerability",
		"description": "Remote code execution",
		"package_name": "requests",
		"version": "2.31.0",
		"advisory_id": "CVE-2024-1234",
		"source_tool": "osv-scanner",
	}]})
	result := admission.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "CVE-2024-1234")
	contains(msg, "requests@2.31.0")
}

# --- T-010: High vulnerability triggers deny ---

test_high_vuln_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "high",
		"category": "vulnerability",
		"description": "SQL injection",
		"package_name": "django",
		"version": "4.2.0",
		"advisory_id": "CVE-2024-5555",
		"source_tool": "trivy",
	}]})
	result := admission.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "CVE-2024-5555")
	contains(msg, "django@4.2.0")
}

# --- T-010: Medium vulnerability triggers warn only, not deny ---

test_medium_vuln_warn_only if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "medium",
		"category": "vulnerability",
		"description": "Information disclosure",
		"package_name": "flask",
		"version": "3.0.0",
		"advisory_id": "CVE-2024-5678",
		"source_tool": "osv-scanner",
	}]})
	deny_result := admission.deny with input as inp
	count(deny_result) == 0
	warn_result := admission.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "CVE-2024-5678")
	contains(msg, "flask@3.0.0")
}

# --- No findings results in allow ---

test_no_findings_approve if {
	deny_result := admission.deny with input as clean_input
	count(deny_result) == 0
	warn_result := admission.warn with input as clean_input
	count(warn_result) == 0
	decision := admission.decision with input as clean_input
	decision == "approve"
}

# --- T-011: Forbidden license triggers deny ---

test_forbidden_license_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "info",
		"category": "license",
		"description": "Package uses GPL-3.0-only license",
		"package_name": "some-gpl-lib",
		"version": "1.0.0",
		"advisory_id": "LIC-001",
		"source_tool": "scancode",
		"license_id": "GPL-3.0-only",
	}]})
	result := admission.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "GPL-3.0-only")
	contains(msg, "some-gpl-lib@1.0.0")
}

# --- T-011: Allowed license does not trigger deny ---

test_allowed_license_no_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "info",
		"category": "license",
		"description": "Package uses MIT license",
		"package_name": "nice-lib",
		"version": "2.0.0",
		"advisory_id": "LIC-002",
		"source_tool": "scancode",
		"license_id": "MIT",
	}]})
	result := admission.deny with input as inp
	count(result) == 0
}

# --- T-011: Package age < 90 days triggers deny ---

test_young_package_deny if {
	# Use a date far in the future so it's always "just published" relative to now
	young_package := object.union(base_package, {
		"first_published_date": "2099-01-01T00:00:00Z",
	})
	inp := object.union(clean_input, {"pkg": young_package})
	result := admission.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "days old")
}

# --- T-011: Package age >= 90 days is allowed ---

test_old_package_no_deny if {
	# 2020-01-01 is well over 90 days old
	result := admission.deny with input as clean_input
	count(result) == 0
}

# --- T-011: MAL- prefixed advisory triggers deny ---

test_malicious_package_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "critical",
		"category": "malware",
		"description": "Known malicious package",
		"package_name": "evil-pkg",
		"version": "0.1.0",
		"advisory_id": "MAL-2024-9999",
		"source_tool": "osv-scanner",
	}]})
	result := admission.deny with input as inp
	some msg in result
	contains(msg, "MAL-2024-9999")
	contains(msg, "evil-pkg@0.1.0")
}

# --- T-011: Transitive deps over threshold triggers warn ---

test_transitive_deps_warn if {
	heavy_package := object.union(base_package, {"transitive_dep_count": 250})
	inp := object.union(clean_input, {"pkg": heavy_package})
	warn_result := admission.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "250")
	contains(msg, "200")
}

# --- Disabled rule does not fire even when condition matches ---

test_disabled_critical_vuln_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"critical_vuln": false},
	)})
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "vulnerability",
			"description": "Remote code execution",
			"package_name": "requests",
			"version": "2.31.0",
			"advisory_id": "CVE-2024-1234",
			"source_tool": "osv-scanner",
		}],
		"pkg": base_package,
		"config": disabled_config,
	}
	deny_result := admission.deny with input as inp
	count(deny_result) == 0
	warn_result := admission.warn with input as inp
	count(warn_result) == 0
}

test_disabled_forbidden_license_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"forbidden_license": false},
	)})
	inp := {
		"findings": [{
			"severity": "info",
			"category": "license",
			"description": "GPL license",
			"package_name": "gpl-lib",
			"version": "1.0.0",
			"advisory_id": "LIC-001",
			"source_tool": "scancode",
			"license_id": "GPL-3.0-only",
		}],
		"pkg": base_package,
		"config": disabled_config,
	}
	result := admission.deny with input as inp
	count(result) == 0
}

test_disabled_malicious_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"malicious_package": false},
	)})
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "malware",
			"description": "Malicious",
			"package_name": "evil-pkg",
			"version": "0.1.0",
			"advisory_id": "MAL-2024-9999",
			"source_tool": "osv-scanner",
		}],
		"pkg": base_package,
		"config": disabled_config,
	}
	result := admission.deny with input as inp
	count(result) == 0
}

# --- Multiple deny reasons are collected ---

test_multiple_deny_reasons if {
	inp := {
		"findings": [
			{
				"severity": "critical",
				"category": "vulnerability",
				"description": "RCE",
				"package_name": "requests",
				"version": "2.31.0",
				"advisory_id": "CVE-2024-1111",
				"source_tool": "osv-scanner",
			},
			{
				"severity": "high",
				"category": "vulnerability",
				"description": "SSRF",
				"package_name": "requests",
				"version": "2.31.0",
				"advisory_id": "CVE-2024-2222",
				"source_tool": "trivy",
			},
			{
				"severity": "info",
				"category": "license",
				"description": "AGPL license",
				"package_name": "agpl-lib",
				"version": "3.0.0",
				"advisory_id": "LIC-010",
				"source_tool": "scancode",
				"license_id": "AGPL-3.0-only",
			},
		],
		"pkg": base_package,
		"config": base_config,
	}
	result := admission.deny with input as inp
	count(result) == 3
}

# --- Decision: reject when deny is non-empty ---

test_decision_reject if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "critical",
		"category": "vulnerability",
		"description": "RCE",
		"package_name": "bad-pkg",
		"version": "0.1.0",
		"advisory_id": "CVE-2024-0001",
		"source_tool": "osv-scanner",
	}]})
	decision := admission.decision with input as inp
	decision == "reject"
}

# --- Decision: approve_with_constraints when only warn ---

test_decision_approve_with_constraints if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "medium",
		"category": "vulnerability",
		"description": "Info leak",
		"package_name": "leaky-lib",
		"version": "1.0.0",
		"advisory_id": "CVE-2024-9999",
		"source_tool": "osv-scanner",
	}]})
	decision := admission.decision with input as inp
	decision == "approve_with_constraints"
}

# --- Decision: approve when no deny and no warn ---

test_decision_approve if {
	decision := admission.decision with input as clean_input
	decision == "approve"
}
