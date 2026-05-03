# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/).

Releases are managed by [release-please](https://github.com/googleapis/release-please).

## [0.2.12](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.11...eedom-v0.2.12) (2026-05-03)


### Features

* add @DetectorRegistry.register decorator to all 15 Phase 1-2 detectors ([eb493d8](https://github.com/gitrdunhq/eedom/commit/eb493d8a8e8d96c51b4a97c47af5b1ea0651ca47))
* add 9 resource-safety opengrep rules (Tier 1) ([8634cc0](https://github.com/gitrdunhq/eedom/commit/8634cc0770446c07693cab6c6ea4301a9f9bd22e))
* add cross-platform container build scripts ([5e8495a](https://github.com/gitrdunhq/eedom/commit/5e8495a4a2d781b638ce52b700568b9a720eb70d))
* add Swift language support ([9410669](https://github.com/gitrdunhq/eedom/commit/9410669d7827907ae5e1bac6d0089f6429ba3896))
* implement 4 core bug detectors (EED-001, EED-004, EED-006, EED-014) ([8448c5b](https://github.com/gitrdunhq/eedom/commit/8448c5b0eece46e0e9c90ed29b5d498aa3e55506))


### Bug Fixes

* add --fast flag for native arm64 builds without scancode ([0e4e1d2](https://github.com/gitrdunhq/eedom/commit/0e4e1d283f706a6e4e5e434df1d9e744191cb385))
* add .swift to complexity runner _SUPPORTED_EXTS ([fdbea91](https://github.com/gitrdunhq/eedom/commit/fdbea91393cfd7c642f58f38635c750b8a913b9d))
* address all review findings (F1-F9) ([61912ce](https://github.com/gitrdunhq/eedom/commit/61912ce79ce40a1d6c56d963bf067de4ca96642f))
* address dom review findings (R1-R5) ([4fd86cd](https://github.com/gitrdunhq/eedom/commit/4fd86cde80868b54b283472e00bbbeac8af1d140))
* build-push tags SHA only, latest reserved for releases ([f186edd](https://github.com/gitrdunhq/eedom/commit/f186edd3cf7f5659149c7211b567c8f0e6a63b09))
* create output parent directory before writing (mkdir -p) ([a38993d](https://github.com/gitrdunhq/eedom/commit/a38993dd3871c023a1da28b5c5b8b4d61c33a0bb))
* DetectorRegistry.discover() now correctly discovers all subpackages ([67159f8](https://github.com/gitrdunhq/eedom/commit/67159f84210834e597442f111a0e952713dc96c3))
* set cspell findings to info severity ([3f27e79](https://github.com/gitrdunhq/eedom/commit/3f27e794cd72f871ab24806650c1d73d855cbfa7))


### Documentation

* add engineer-output.json delivery summary ([4322ca0](https://github.com/gitrdunhq/eedom/commit/4322ca0104f13d3d3c1ad0226b64cb04b51302b9))

## [0.2.11](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.10...eedom-v0.2.11) (2026-04-30)


### Bug Fixes

* skip CI for draft PRs ([87c7efd](https://github.com/gitrdunhq/eedom/commit/87c7efd60ae0c9b4246c0b6631bdc45aaef335ec))

## [0.2.10](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.9...eedom-v0.2.10) (2026-04-30)


### Features

* add solver module — LLM-powered detector test generation via OpenRouter ([6335c47](https://github.com/gitrdunhq/eedom/commit/6335c4742c0bd2e7d00feecb6865f60ce744cae1))


### Bug Fixes

* address all 22 review findings (low to critical) ([6af16eb](https://github.com/gitrdunhq/eedom/commit/6af16ebb9c10b59a0357a64b83940e7bb728c003))
* include template files in wheel distribution ([#275](https://github.com/gitrdunhq/eedom/issues/275)) ([b3d6b3a](https://github.com/gitrdunhq/eedom/commit/b3d6b3a01a1d65701bb3c5a991cae32cc5b74e37))
* Pydantic boundary contracts for solver module ([b6552de](https://github.com/gitrdunhq/eedom/commit/b6552def633698b4566ba47c6ecf2a4566a2d663))

## [0.2.9](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.8...eedom-v0.2.9) (2026-04-29)


### Features

* add --scope flag for diff-scoped and folder-scoped scanning ([f25b351](https://github.com/gitrdunhq/eedom/commit/f25b351a9523d297bef4d60c0e90e159017a41f5))
* Alley-Oop — holistic trust audit, 4-wave remediation, OpenRouter free models ([cb8d9a7](https://github.com/gitrdunhq/eedom/commit/cb8d9a7f60df7a78902f441376b5af3002f74fcc))
* migrate renderers behind ReportRendererPort (MarkdownRenderer, SarifRenderer, JsonRenderer) ([3dccc4d](https://github.com/gitrdunhq/eedom/commit/3dccc4d67aaabae15016ed92f04e3d896f86a842))
* replace semgrep with opengrep — local rules only, no registry dependency ([d46c762](https://github.com/gitrdunhq/eedom/commit/d46c7622785b4ed00b34c93b3b3b8c1d9602627d))


### Bug Fixes

* add concurrency group to release-please to prevent branch race ([2f4a050](https://github.com/gitrdunhq/eedom/commit/2f4a0506dc521d7520b1823ea6fc86a45c83bd6c))
* add e2e tests to GATEKEEPER CI gate (container-only) ([2518a70](https://github.com/gitrdunhq/eedom/commit/2518a70c02a5df4c9b45bd714bff4451d6d08351))
* address 12 Copilot/Torvalds review findings ([95e4b7c](https://github.com/gitrdunhq/eedom/commit/95e4b7c4f789acb5d3d036044a165334da116309))
* address PR review — sha256 verify opengrep, rename log events, remove dead code ([9d9d4f3](https://github.com/gitrdunhq/eedom/commit/9d9d4f38eee3ba1c9e4611a6d9078f5dfab7a8d4))
* cpd XML parser + cspell output capture + CI pytest install ([d7cbc04](https://github.com/gitrdunhq/eedom/commit/d7cbc04280a99cbbfa18a541d96a80d65f0239c1))
* cspell drop dictionary args that cause silent failure with JSON reporter ([a3adac5](https://github.com/gitrdunhq/eedom/commit/a3adac57e122e29f8b6ed64b41b02261b71264f2))
* cspell JSON reporter + migrate CI to x86 runner ([fb5d1cf](https://github.com/gitrdunhq/eedom/commit/fb5d1cfe18229a719c68d97c67954d66da2897cc))
* cspell minimal flags — only --reporter for JSON stdout capture ([a91a925](https://github.com/gitrdunhq/eedom/commit/a91a925a357e14e560dfe58b4a1b6d0139625fc4))
* cspell runs from repo_path with relative file paths ([735e46b](https://github.com/gitrdunhq/eedom/commit/735e46bd0ad77393a12bfb7c7f723c7f5fdf0790))
* cspell use JSON reporter for reliable subprocess capture ([b862809](https://github.com/gitrdunhq/eedom/commit/b862809e4f449170c1eaf9b382393b11c1259a15))
* cspell use temp config file with JSON reporter outFile ([f1efc32](https://github.com/gitrdunhq/eedom/commit/f1efc32cc3e30f8cdfc9388b3a9a338fcc803904))
* cspell write JSON to file — bypass Node.js TTY buffering ([a75f139](https://github.com/gitrdunhq/eedom/commit/a75f139d5f5842d8d3d6353a1c432d9106c4c31d))
* disable auto-done workflow until project bot PAT gets project scope ([951c960](https://github.com/gitrdunhq/eedom/commit/951c960b62945cc3a625d45b04cf7a30e3023ef9))
* disable clamav from default scanners — not useful for source code review ([479622a](https://github.com/gitrdunhq/eedom/commit/479622a26ff2670922f6219dbe1fe07f274897ef))
* disable clamav in repo config, re-enable cspell ([59e2b3a](https://github.com/gitrdunhq/eedom/commit/59e2b3a3488281db2733654b808fae2ba70f4250))
* disable cspell plugin + xfail e2e test — Node.js TTY buffering issue tracked ([74045ab](https://github.com/gitrdunhq/eedom/commit/74045aba1723ad077bce5554270ea578c6edb8b5))
* exclude test fixtures from self-review — planted vulns were triggering GATEKEEPER gate ([1a964c5](https://github.com/gitrdunhq/eedom/commit/1a964c5402bd9fc30ea164e6b426572f94e18320))
* gitleaks renderer KeyError + cpd/cspell skip when not installed ([0103ded](https://github.com/gitrdunhq/eedom/commit/0103ded155b3830f0688dff804299a9eaba38099))
* make all 1492 tests pass in container — zero failures ([fa6ec0b](https://github.com/gitrdunhq/eedom/commit/fa6ec0b082e6ce556594290704764a78154162e3))
* mark deterministic bug detectors as xfail — zero confusing failures ([b993f8b](https://github.com/gitrdunhq/eedom/commit/b993f8b4e6cd73441171b741d8a3b6564d07add8))
* OPA policy path points to policy.rego, not ./policies/ dir (D1) ([57ef054](https://github.com/gitrdunhq/eedom/commit/57ef054c48b59a3bf16322d4cefec066f0417b9c))
* parallelize CI, switch to GH-hosted runners, eliminate push-to-main duplication ([49e7af0](https://github.com/gitrdunhq/eedom/commit/49e7af0c02c9737b0ec7608acc3a4b6694eac4e5))
* pin release-please to x86 runner, deregister Mac runner ([2aff4cf](https://github.com/gitrdunhq/eedom/commit/2aff4cf5995bc25270687214c9c8940015a168ed))
* PYTHONPATH=/workspace/src in CI so e2e tests use PR source, not stale container code ([f475c4c](https://github.com/gitrdunhq/eedom/commit/f475c4cfa53ce90be98a31cc25755f1449376671))
* repair gitleaks, CPD, and cspell output capture on arm64 ([ebeb33b](https://github.com/gitrdunhq/eedom/commit/ebeb33bd01324f800ca18d9e0a4b0cd1ed23ac2a))
* repair gitleaks, CPD, cspell output capture + tighten e2e assertions ([b52b623](https://github.com/gitrdunhq/eedom/commit/b52b623bfbc77ae468747c78855c893178e86948))
* restore registry rulesets for max coverage while building local replacements ([d0e3187](https://github.com/gitrdunhq/eedom/commit/d0e31874b9b45c428a2fd09f256d404aba8ba94c))
* revert scanner skip — fail loud when cpd/cspell missing from container ([33e2e8f](https://github.com/gitrdunhq/eedom/commit/33e2e8f5aedb5138118ab466aa861caa9f06bf5a))
* run eedom review as root in Docker — UID mismatch on .temp mount ([e7b2f3b](https://github.com/gitrdunhq/eedom/commit/e7b2f3b41e62712d523dd748574d7bdca2e9ac82))
* trivy respects .eedomignore via --skip-dirs, drop .trivyignore ([c2faaa1](https://github.com/gitrdunhq/eedom/commit/c2faaa18a7641cd899e16a228eaf29355bfe6c3b))
* trivy skip-dirs tests use ToolRunnerPort mock instead of subprocess ([0eb8be5](https://github.com/gitrdunhq/eedom/commit/0eb8be573ac57ed77eae57af8542700f5f367d4d))
* trivyignore for test fixtures + chown clamav dirs for root user ([e42d3c7](https://github.com/gitrdunhq/eedom/commit/e42d3c751a473df80433f698cd43b71e84a691d9))
* update gitleaks unit tests for temp-file report + add codebase-stats.py ([4365d05](https://github.com/gitrdunhq/eedom/commit/4365d05efd65fdb1685b79c18aa3fe962726e982))
* update gitleaks unit tests for temp-file report + add codebase-stats.py ([a72c2a8](https://github.com/gitrdunhq/eedom/commit/a72c2a83ee512374c7b1c220357e45c0fbe3e98d))
* xfail semgrep e2e — container has 1.67.0, registry requires &gt;=1.76.0 ([46c2ee4](https://github.com/gitrdunhq/eedom/commit/46c2ee44443a5e8dd757f660f7615e2024f7c9ba))


### Documentation

* add AGENTS.md — codified agent execution model, split TDD, self-review ([3f1fa15](https://github.com/gitrdunhq/eedom/commit/3f1fa154f98af75d13d0e1e78329618c73843798))
* add dogfood findings log — 3 bugs found in self-scan ([4c8b778](https://github.com/gitrdunhq/eedom/commit/4c8b778f9cb45674e50cfdd46cef08cfde64eef5))
* add split-TDD rule + container-only testing to CLAUDE.md ([789463b](https://github.com/gitrdunhq/eedom/commit/789463bbdfb9929467f81e90a8f4facebd34a620))
* dogfood run 2 — D1 fixed, no new bugs from P2/P4 ([acb6ad6](https://github.com/gitrdunhq/eedom/commit/acb6ad6e88d1bef169c076176bf5f8c7886e8967))
* quality over speed — no RED+GREEN shortcuts, no exceptions ([39c0633](https://github.com/gitrdunhq/eedom/commit/39c0633548e81630061a279e4e321ba80ebe80e8))

## [0.2.8](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.7...eedom-v0.2.8) (2026-04-28)


### Bug Fixes

* modernize Dockerfile — venv, lockfile installs, amd64 checksums (closes [#141](https://github.com/gitrdunhq/eedom/issues/141)) ([e95540d](https://github.com/gitrdunhq/eedom/commit/e95540dcee18c2fd1f0c348eb142dc68154502ad))
* tie version strings to importlib.metadata (closes [#194](https://github.com/gitrdunhq/eedom/issues/194)) ([9500d53](https://github.com/gitrdunhq/eedom/commit/9500d53206c4e83ab493836707d4b343f064ca7f))

## [0.2.7](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.6...eedom-v0.2.7) (2026-04-28)


### Features

* --format json structured output for machine consumption (closes [#92](https://github.com/gitrdunhq/eedom/issues/92)) ([74b0a44](https://github.com/gitrdunhq/eedom/commit/74b0a4488427b83e7373bad3dc5bc6418e179b98))
* actionability classification for scanner findings ([a865ac7](https://github.com/gitrdunhq/eedom/commit/a865ac7c6c8109b0d3e331a8031b4f913eb15bcc))
* add DPS-12 property-based testing standard — 14 domains, formal property types ([#39](https://github.com/gitrdunhq/eedom/issues/39)) ([d99ca66](https://github.com/gitrdunhq/eedom/commit/d99ca669e3a1f43e18b876b6b75e1a581e2afa43))
* cfn-nag + cdk-nag plugins — AWS CloudFormation/CDK security scanning (STORM + HAWK) ([6ca9943](https://github.com/gitrdunhq/eedom/commit/6ca9943fdeed2305803f5eb32a02e61da154f33f))
* configurable fan-out threshold via .eagle-eyed-dom.yaml (closes [#95](https://github.com/gitrdunhq/eedom/issues/95)) ([32df0c2](https://github.com/gitrdunhq/eedom/commit/32df0c2cda29a2f98ff3ca7fd541ecdfb5ac9d88))
* **container:** 18/18 scanners, Trixie base, Node 22, binary bumps ([312bbf1](https://github.com/gitrdunhq/eedom/commit/312bbf19d04a465a5c32194644fcd22435c7e173))
* eedom v1.2.0 — clean scanner repo, split from securePackages ([acf67fc](https://github.com/gitrdunhq/eedom/commit/acf67fc587538e002363a6dc79dc27214fa58a32))
* mypy/pyright plugin + enforce container-only test execution ([#41](https://github.com/gitrdunhq/eedom/issues/41)) ([7e85a2d](https://github.com/gitrdunhq/eedom/commit/7e85a2d59223052a333bbb98bafbff67b17167ad)), closes [#37](https://github.com/gitrdunhq/eedom/issues/37)
* native PR review posting — inline comments from SARIF ([#25](https://github.com/gitrdunhq/eedom/issues/25)) ([70bac2a](https://github.com/gitrdunhq/eedom/commit/70bac2a17f0a22293aada9f641a447f2ea3bba4b))
* security hardening — gitleaks PII, two-key release gate, SLSA attestation, SBOM, weekly dogfood ([9d32b49](https://github.com/gitrdunhq/eedom/commit/9d32b4912c815cdea41798426159b18fa1dcf169))
* separate security score from quality score — quality plugins are advisory, not merge-blocking ([0185d24](https://github.com/gitrdunhq/eedom/commit/0185d242544542866c408200da8d3167c2007ade))
* skip reasons in PluginResult — why scanners were skipped + remediation (closes [#88](https://github.com/gitrdunhq/eedom/issues/88)) ([e4bdf72](https://github.com/gitrdunhq/eedom/commit/e4bdf72aed908a2dd10ce57f5a6ba74850fcd370))
* SLSA Level 3 build provenance for container images ([#29](https://github.com/gitrdunhq/eedom/issues/29)) ([#30](https://github.com/gitrdunhq/eedom/issues/30)) ([7338837](https://github.com/gitrdunhq/eedom/commit/7338837fc44190a02cc73e0daa31ceb16be0ecb2))
* two-axis scoring — security blocks, quality advises (closes [#93](https://github.com/gitrdunhq/eedom/issues/93)) ([76bf07a](https://github.com/gitrdunhq/eedom/commit/76bf07adc793fa0ccba3d8af85fbaaf33ead9e46))
* validate SARIF line numbers against PR diff hunks + SMART inline comments ([#34](https://github.com/gitrdunhq/eedom/issues/34)) ([9d7fe8c](https://github.com/gitrdunhq/eedom/commit/9d7fe8c7d398f1b91bb2ef0113575460369cf9dd))


### Bug Fixes

* add .dogfood to manifest discovery skip list ([9ceb79e](https://github.com/gitrdunhq/eedom/commit/9ceb79eac59ff08fe321965304d84b33c3a282a6))
* add severity to unpinned dependency findings — critical for unversioned, high for ranges ([c14df35](https://github.com/gitrdunhq/eedom/commit/c14df357824d33e12b068334a20dc9d97309604d))
* address 3 Codex findings — cfn-nag returncode, stale cdk.out, JSON discovery (ICE + BLAZE + TURBO) ([72dc2b5](https://github.com/gitrdunhq/eedom/commit/72dc2b5a46df35be1bfe1a2a5108df508292ef88))
* address 7 Copilot findings — shell injection, missing perms, fork guard, SHA pinning, PR-context gates ([de144ad](https://github.com/gitrdunhq/eedom/commit/de144ad84556c2989f5b9d175d4acfae7a8751ec))
* auto-file issue on incomplete review — links to crashed PR and run ([863ef80](https://github.com/gitrdunhq/eedom/commit/863ef80db2c2545b8b34eff7acce1cd157134f79))
* blast-radius read-only filesystem crash + clamav exit-2 silent failure ([#33](https://github.com/gitrdunhq/eedom/issues/33)) ([b11d39f](https://github.com/gitrdunhq/eedom/commit/b11d39fe88e3565e1ec52dde43719f595f696892))
* cdk-nag assembly-only mode — skip synth when no cdk.json (closes [#80](https://github.com/gitrdunhq/eedom/issues/80)) ([ab7f227](https://github.com/gitrdunhq/eedom/commit/ab7f2271d9bc7d110f9300e1f2d66c153ce550ea))
* container build — add LICENSE for hatchling + local eedom:latest tag ([d77fb15](https://github.com/gitrdunhq/eedom/commit/d77fb154e71dcfd1ef2257b65012918bfd88790f))
* Copilot request failure adds dom: needs-copilot label + comment ([7155646](https://github.com/gitrdunhq/eedom/commit/715564660c6b74b685a8c1cdc8cc249cfd34df90))
* correct pypi-publish action SHA pin — v1.14.0 ([0ef8145](https://github.com/gitrdunhq/eedom/commit/0ef81450882c05ab4d37933084ad51b7e8fdf530))
* cyclonedx-py CLI flags + non-blocking SBOM generation ([5116145](https://github.com/gitrdunhq/eedom/commit/5116145dd484ee8c31bb28d8010ef0dcc8654592))
* **docker:** copy README.md into build context for hatchling metadata ([2c5a19f](https://github.com/gitrdunhq/eedom/commit/2c5a19f3f8c64059a81a8beba0f055cc864570be))
* docs-only PR skip, Jinja2 nosemgrep, complexity render cap (closes [#84](https://github.com/gitrdunhq/eedom/issues/84), [#87](https://github.com/gitrdunhq/eedom/issues/87), [#59](https://github.com/gitrdunhq/eedom/issues/59)) ([f9726ed](https://github.com/gitrdunhq/eedom/commit/f9726ed88e464507969976a3dc0b92a0e7f07cc0))
* document intentional single-commit gitleaks scan ([5757470](https://github.com/gitrdunhq/eedom/commit/5757470e928d9b13c5ae045043f38a59e2715a51))
* exclude cdk.out/ from discovery + add .json to watch mode ([#81](https://github.com/gitrdunhq/eedom/issues/81)) ([14a1912](https://github.com/gitrdunhq/eedom/commit/14a1912c17761451efbf55c6fc9f0df98e3a2a12))
* expand DEFAULT_PATTERNS with build artifacts, IDE, agent state dirs ([#85](https://github.com/gitrdunhq/eedom/issues/85)) ([1ee1def](https://github.com/gitrdunhq/eedom/commit/1ee1def4c75eb836b46f5f52a010800088e2cfca))
* fail-closed GATEKEEPER — emit plugin errors in SARIF + block on crashed scanners ([1dc84fe](https://github.com/gitrdunhq/eedom/commit/1dc84fe058e352a1323cbdfaf95ed7d3f9cb232e))
* fail-open crash threshold — dom: incomplete when 3+ plugins crash ([94380f6](https://github.com/gitrdunhq/eedom/commit/94380f63a30060f0bacb48fcfd058b7dfe076eaf))
* include .j2 templates in wheel — artifacts config for hatchling ([6306d54](https://github.com/gitrdunhq/eedom/commit/6306d543d7eef4aee9a83f2219aa5e8e8beb1b0b))
* include Jinja2 templates in wheel + gitleaks custom config support ([#31](https://github.com/gitrdunhq/eedom/issues/31)) ([d253185](https://github.com/gitrdunhq/eedom/commit/d253185aa0b165cdfe40ec59d52656633801c169))
* move all GH Actions interpolations to env blocks — eliminate shell injection ([1987dc5](https://github.com/gitrdunhq/eedom/commit/1987dc594f57bd83488e5e3557853d7d061a5881))
* pin GitHub Actions to full commit SHAs — org policy requires it ([b7f8329](https://github.com/gitrdunhq/eedom/commit/b7f83292c11837f113d137de542104a163ca4812))
* publish job needs ubuntu-latest — pypi-publish action requires Linux ([f311cc3](https://github.com/gitrdunhq/eedom/commit/f311cc38b4c241413bf910232728fdeb3b209044))
* remove --add-reviewer [@copilot](https://github.com/copilot) from CI — GITHUB_TOKEN lacks permission ([af79ebd](https://github.com/gitrdunhq/eedom/commit/af79ebd29ccf4abac92bf35324669231fd9e70a3))
* render report sections security-first by category priority ([#89](https://github.com/gitrdunhq/eedom/issues/89)) ([644492e](https://github.com/gitrdunhq/eedom/commit/644492e978159fcec03ab10731e53e221bf1c0a6))
* repair double-word stutters from admission rename ([#6](https://github.com/gitrdunhq/eedom/issues/6)) ([f098504](https://github.com/gitrdunhq/eedom/commit/f09850471ca32d4f270e06bee22a3bdb49cd6601))
* resolve all 14 dogfood findings ([#22](https://github.com/gitrdunhq/eedom/issues/22)) ([d1a19c3](https://github.com/gitrdunhq/eedom/commit/d1a19c367660016d80bedd432ca1519d5ce2a12b))
* run GATEKEEPER on all PRs + fix broken markdown table ([ba7c52d](https://github.com/gitrdunhq/eedom/commit/ba7c52dd09b621631ba167fc4b1719eb16431bf1))
* scanner runners fail-LOUD on bad JSON + CI workflow hardening ([7870e32](https://github.com/gitrdunhq/eedom/commit/7870e32c99914cfb9ec0297b8d5b3b3d9bf67a68))
* semgrep subprocess-no-timeout false positives + 3 new rules ([#13](https://github.com/gitrdunhq/eedom/issues/13)) ([9872a3d](https://github.com/gitrdunhq/eedom/commit/9872a3dbf007f38ac1006db493c63dc6df9475f3))
* skip GATEKEEPER on release-please PRs ([1a08d25](https://github.com/gitrdunhq/eedom/commit/1a08d2595964f318542a682d68047807c1b2efc9))
* SLSA attestation non-blocking on self-hosted runners (closes [#105](https://github.com/gitrdunhq/eedom/issues/105)) ([fd9f1c6](https://github.com/gitrdunhq/eedom/commit/fd9f1c6da25091da64e20894940c69517ebfd524))
* top 10 dogfood findings — eedom self-heals ([#8](https://github.com/gitrdunhq/eedom/issues/8)) ([9b7a839](https://github.com/gitrdunhq/eedom/commit/9b7a8398410a685b30c75d2cdc4b72f78b81b7d8))
* try requesting Copilot review, fail silently if token lacks permission ([12860f8](https://github.com/gitrdunhq/eedom/commit/12860f8be0aa0beee63ab4c58e0ddb465f2ec332))


### Documentation

* add commit message discipline to CLAUDE.md ([e6cfca1](https://github.com/gitrdunhq/eedom/commit/e6cfca1a5a91b2a4f78ea608427362e1c251ef86))
* explain telemetry value — eedom dogfoods itself, human-triaged bug fixing in realtime ([583c487](https://github.com/gitrdunhq/eedom/commit/583c48701e100f6701ae986788ba2a039dc20e07))
* plugin prose — security (gates merges) and quality (advisory) with severity tables ([f1e0874](https://github.com/gitrdunhq/eedom/commit/f1e0874ff2bcdaa90cacd8f8293cce0f170b1c17))
* rewrite elevator pitch — cognitive burden reduction for engineering teams ([79f3144](https://github.com/gitrdunhq/eedom/commit/79f3144578608b2e3f16f4abb71fe7e3c28c5488))
* telemetry modes — community (contribute back) vs self-heal (internal only) ([aaf3200](https://github.com/gitrdunhq/eedom/commit/aaf32001e474652a46b0c382207b1ee0228f70ee))
* update plugin counts to 18 + add capability matrix reference ([a202c17](https://github.com/gitrdunhq/eedom/commit/a202c1703e56e28207e246ac3c3c2825e157c18b))

## [0.2.6](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.5...eedom-v0.2.6) (2026-04-28)


### Features

* --format json structured output for machine consumption (closes [#92](https://github.com/gitrdunhq/eedom/issues/92)) ([74b0a44](https://github.com/gitrdunhq/eedom/commit/74b0a4488427b83e7373bad3dc5bc6418e179b98))
* configurable fan-out threshold via .eagle-eyed-dom.yaml (closes [#95](https://github.com/gitrdunhq/eedom/issues/95)) ([32df0c2](https://github.com/gitrdunhq/eedom/commit/32df0c2cda29a2f98ff3ca7fd541ecdfb5ac9d88))
* skip reasons in PluginResult — why scanners were skipped + remediation (closes [#88](https://github.com/gitrdunhq/eedom/issues/88)) ([e4bdf72](https://github.com/gitrdunhq/eedom/commit/e4bdf72aed908a2dd10ce57f5a6ba74850fcd370))
* two-axis scoring — security blocks, quality advises (closes [#93](https://github.com/gitrdunhq/eedom/issues/93)) ([76bf07a](https://github.com/gitrdunhq/eedom/commit/76bf07adc793fa0ccba3d8af85fbaaf33ead9e46))


### Bug Fixes

* cdk-nag assembly-only mode — skip synth when no cdk.json (closes [#80](https://github.com/gitrdunhq/eedom/issues/80)) ([ab7f227](https://github.com/gitrdunhq/eedom/commit/ab7f2271d9bc7d110f9300e1f2d66c153ce550ea))
* docs-only PR skip, Jinja2 nosemgrep, complexity render cap (closes [#84](https://github.com/gitrdunhq/eedom/issues/84), [#87](https://github.com/gitrdunhq/eedom/issues/87), [#59](https://github.com/gitrdunhq/eedom/issues/59)) ([f9726ed](https://github.com/gitrdunhq/eedom/commit/f9726ed88e464507969976a3dc0b92a0e7f07cc0))
* SLSA attestation non-blocking on self-hosted runners (closes [#105](https://github.com/gitrdunhq/eedom/issues/105)) ([fd9f1c6](https://github.com/gitrdunhq/eedom/commit/fd9f1c6da25091da64e20894940c69517ebfd524))


### Documentation

* add commit message discipline to CLAUDE.md ([e6cfca1](https://github.com/gitrdunhq/eedom/commit/e6cfca1a5a91b2a4f78ea608427362e1c251ef86))

## [0.2.5](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.4...eedom-v0.2.5) (2026-04-27)


### Features

* actionability classification for scanner findings ([a865ac7](https://github.com/gitrdunhq/eedom/commit/a865ac7c6c8109b0d3e331a8031b4f913eb15bcc))
* **container:** 18/18 scanners, Trixie base, Node 22, binary bumps ([312bbf1](https://github.com/gitrdunhq/eedom/commit/312bbf19d04a465a5c32194644fcd22435c7e173))


### Bug Fixes

* skip GATEKEEPER on release-please PRs ([1a08d25](https://github.com/gitrdunhq/eedom/commit/1a08d2595964f318542a682d68047807c1b2efc9))

## [0.2.4](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.3...eedom-v0.2.4) (2026-04-27)


### Features

* add DPS-12 property-based testing standard — 14 domains, formal property types ([#39](https://github.com/gitrdunhq/eedom/issues/39)) ([d99ca66](https://github.com/gitrdunhq/eedom/commit/d99ca669e3a1f43e18b876b6b75e1a581e2afa43))
* cfn-nag + cdk-nag plugins — AWS CloudFormation/CDK security scanning (STORM + HAWK) ([6ca9943](https://github.com/gitrdunhq/eedom/commit/6ca9943fdeed2305803f5eb32a02e61da154f33f))
* eedom v1.2.0 — clean scanner repo, split from securePackages ([acf67fc](https://github.com/gitrdunhq/eedom/commit/acf67fc587538e002363a6dc79dc27214fa58a32))
* mypy/pyright plugin + enforce container-only test execution ([#41](https://github.com/gitrdunhq/eedom/issues/41)) ([7e85a2d](https://github.com/gitrdunhq/eedom/commit/7e85a2d59223052a333bbb98bafbff67b17167ad)), closes [#37](https://github.com/gitrdunhq/eedom/issues/37)
* native PR review posting — inline comments from SARIF ([#25](https://github.com/gitrdunhq/eedom/issues/25)) ([70bac2a](https://github.com/gitrdunhq/eedom/commit/70bac2a17f0a22293aada9f641a447f2ea3bba4b))
* security hardening — gitleaks PII, two-key release gate, SLSA attestation, SBOM, weekly dogfood ([9d32b49](https://github.com/gitrdunhq/eedom/commit/9d32b4912c815cdea41798426159b18fa1dcf169))
* separate security score from quality score — quality plugins are advisory, not merge-blocking ([0185d24](https://github.com/gitrdunhq/eedom/commit/0185d242544542866c408200da8d3167c2007ade))
* SLSA Level 3 build provenance for container images ([#29](https://github.com/gitrdunhq/eedom/issues/29)) ([#30](https://github.com/gitrdunhq/eedom/issues/30)) ([7338837](https://github.com/gitrdunhq/eedom/commit/7338837fc44190a02cc73e0daa31ceb16be0ecb2))
* validate SARIF line numbers against PR diff hunks + SMART inline comments ([#34](https://github.com/gitrdunhq/eedom/issues/34)) ([9d7fe8c](https://github.com/gitrdunhq/eedom/commit/9d7fe8c7d398f1b91bb2ef0113575460369cf9dd))


### Bug Fixes

* add .dogfood to manifest discovery skip list ([9ceb79e](https://github.com/gitrdunhq/eedom/commit/9ceb79eac59ff08fe321965304d84b33c3a282a6))
* add severity to unpinned dependency findings — critical for unversioned, high for ranges ([c14df35](https://github.com/gitrdunhq/eedom/commit/c14df357824d33e12b068334a20dc9d97309604d))
* address 3 Codex findings — cfn-nag returncode, stale cdk.out, JSON discovery (ICE + BLAZE + TURBO) ([72dc2b5](https://github.com/gitrdunhq/eedom/commit/72dc2b5a46df35be1bfe1a2a5108df508292ef88))
* address 7 Copilot findings — shell injection, missing perms, fork guard, SHA pinning, PR-context gates ([de144ad](https://github.com/gitrdunhq/eedom/commit/de144ad84556c2989f5b9d175d4acfae7a8751ec))
* auto-file issue on incomplete review — links to crashed PR and run ([863ef80](https://github.com/gitrdunhq/eedom/commit/863ef80db2c2545b8b34eff7acce1cd157134f79))
* blast-radius read-only filesystem crash + clamav exit-2 silent failure ([#33](https://github.com/gitrdunhq/eedom/issues/33)) ([b11d39f](https://github.com/gitrdunhq/eedom/commit/b11d39fe88e3565e1ec52dde43719f595f696892))
* container build — add LICENSE for hatchling + local eedom:latest tag ([d77fb15](https://github.com/gitrdunhq/eedom/commit/d77fb154e71dcfd1ef2257b65012918bfd88790f))
* Copilot request failure adds dom: needs-copilot label + comment ([7155646](https://github.com/gitrdunhq/eedom/commit/715564660c6b74b685a8c1cdc8cc249cfd34df90))
* correct pypi-publish action SHA pin — v1.14.0 ([0ef8145](https://github.com/gitrdunhq/eedom/commit/0ef81450882c05ab4d37933084ad51b7e8fdf530))
* cyclonedx-py CLI flags + non-blocking SBOM generation ([5116145](https://github.com/gitrdunhq/eedom/commit/5116145dd484ee8c31bb28d8010ef0dcc8654592))
* **docker:** copy README.md into build context for hatchling metadata ([2c5a19f](https://github.com/gitrdunhq/eedom/commit/2c5a19f3f8c64059a81a8beba0f055cc864570be))
* document intentional single-commit gitleaks scan ([5757470](https://github.com/gitrdunhq/eedom/commit/5757470e928d9b13c5ae045043f38a59e2715a51))
* exclude cdk.out/ from discovery + add .json to watch mode ([#81](https://github.com/gitrdunhq/eedom/issues/81)) ([14a1912](https://github.com/gitrdunhq/eedom/commit/14a1912c17761451efbf55c6fc9f0df98e3a2a12))
* expand DEFAULT_PATTERNS with build artifacts, IDE, agent state dirs ([#85](https://github.com/gitrdunhq/eedom/issues/85)) ([1ee1def](https://github.com/gitrdunhq/eedom/commit/1ee1def4c75eb836b46f5f52a010800088e2cfca))
* fail-closed GATEKEEPER — emit plugin errors in SARIF + block on crashed scanners ([1dc84fe](https://github.com/gitrdunhq/eedom/commit/1dc84fe058e352a1323cbdfaf95ed7d3f9cb232e))
* fail-open crash threshold — dom: incomplete when 3+ plugins crash ([94380f6](https://github.com/gitrdunhq/eedom/commit/94380f63a30060f0bacb48fcfd058b7dfe076eaf))
* include .j2 templates in wheel — artifacts config for hatchling ([6306d54](https://github.com/gitrdunhq/eedom/commit/6306d543d7eef4aee9a83f2219aa5e8e8beb1b0b))
* include Jinja2 templates in wheel + gitleaks custom config support ([#31](https://github.com/gitrdunhq/eedom/issues/31)) ([d253185](https://github.com/gitrdunhq/eedom/commit/d253185aa0b165cdfe40ec59d52656633801c169))
* move all GH Actions interpolations to env blocks — eliminate shell injection ([1987dc5](https://github.com/gitrdunhq/eedom/commit/1987dc594f57bd83488e5e3557853d7d061a5881))
* pin GitHub Actions to full commit SHAs — org policy requires it ([b7f8329](https://github.com/gitrdunhq/eedom/commit/b7f83292c11837f113d137de542104a163ca4812))
* publish job needs ubuntu-latest — pypi-publish action requires Linux ([f311cc3](https://github.com/gitrdunhq/eedom/commit/f311cc38b4c241413bf910232728fdeb3b209044))
* remove --add-reviewer [@copilot](https://github.com/copilot) from CI — GITHUB_TOKEN lacks permission ([af79ebd](https://github.com/gitrdunhq/eedom/commit/af79ebd29ccf4abac92bf35324669231fd9e70a3))
* render report sections security-first by category priority ([#89](https://github.com/gitrdunhq/eedom/issues/89)) ([644492e](https://github.com/gitrdunhq/eedom/commit/644492e978159fcec03ab10731e53e221bf1c0a6))
* repair double-word stutters from admission rename ([#6](https://github.com/gitrdunhq/eedom/issues/6)) ([f098504](https://github.com/gitrdunhq/eedom/commit/f09850471ca32d4f270e06bee22a3bdb49cd6601))
* resolve all 14 dogfood findings ([#22](https://github.com/gitrdunhq/eedom/issues/22)) ([d1a19c3](https://github.com/gitrdunhq/eedom/commit/d1a19c367660016d80bedd432ca1519d5ce2a12b))
* run GATEKEEPER on all PRs + fix broken markdown table ([ba7c52d](https://github.com/gitrdunhq/eedom/commit/ba7c52dd09b621631ba167fc4b1719eb16431bf1))
* scanner runners fail-LOUD on bad JSON + CI workflow hardening ([7870e32](https://github.com/gitrdunhq/eedom/commit/7870e32c99914cfb9ec0297b8d5b3b3d9bf67a68))
* semgrep subprocess-no-timeout false positives + 3 new rules ([#13](https://github.com/gitrdunhq/eedom/issues/13)) ([9872a3d](https://github.com/gitrdunhq/eedom/commit/9872a3dbf007f38ac1006db493c63dc6df9475f3))
* top 10 dogfood findings — eedom self-heals ([#8](https://github.com/gitrdunhq/eedom/issues/8)) ([9b7a839](https://github.com/gitrdunhq/eedom/commit/9b7a8398410a685b30c75d2cdc4b72f78b81b7d8))
* try requesting Copilot review, fail silently if token lacks permission ([12860f8](https://github.com/gitrdunhq/eedom/commit/12860f8be0aa0beee63ab4c58e0ddb465f2ec332))


### Documentation

* explain telemetry value — eedom dogfoods itself, human-triaged bug fixing in realtime ([583c487](https://github.com/gitrdunhq/eedom/commit/583c48701e100f6701ae986788ba2a039dc20e07))
* plugin prose — security (gates merges) and quality (advisory) with severity tables ([f1e0874](https://github.com/gitrdunhq/eedom/commit/f1e0874ff2bcdaa90cacd8f8293cce0f170b1c17))
* rewrite elevator pitch — cognitive burden reduction for engineering teams ([79f3144](https://github.com/gitrdunhq/eedom/commit/79f3144578608b2e3f16f4abb71fe7e3c28c5488))
* telemetry modes — community (contribute back) vs self-heal (internal only) ([aaf3200](https://github.com/gitrdunhq/eedom/commit/aaf32001e474652a46b0c382207b1ee0228f70ee))
* update plugin counts to 18 + add capability matrix reference ([a202c17](https://github.com/gitrdunhq/eedom/commit/a202c1703e56e28207e246ac3c3c2825e157c18b))

## [0.2.3](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.2...eedom-v0.2.3) (2026-04-27)


### Features

* add DPS-12 property-based testing standard — 14 domains, formal property types ([#39](https://github.com/gitrdunhq/eedom/issues/39)) ([d99ca66](https://github.com/gitrdunhq/eedom/commit/d99ca669e3a1f43e18b876b6b75e1a581e2afa43))
* cfn-nag + cdk-nag plugins — AWS CloudFormation/CDK security scanning (STORM + HAWK) ([6ca9943](https://github.com/gitrdunhq/eedom/commit/6ca9943fdeed2305803f5eb32a02e61da154f33f))
* eedom v1.2.0 — clean scanner repo, split from securePackages ([acf67fc](https://github.com/gitrdunhq/eedom/commit/acf67fc587538e002363a6dc79dc27214fa58a32))
* mypy/pyright plugin + enforce container-only test execution ([#41](https://github.com/gitrdunhq/eedom/issues/41)) ([7e85a2d](https://github.com/gitrdunhq/eedom/commit/7e85a2d59223052a333bbb98bafbff67b17167ad)), closes [#37](https://github.com/gitrdunhq/eedom/issues/37)
* native PR review posting — inline comments from SARIF ([#25](https://github.com/gitrdunhq/eedom/issues/25)) ([70bac2a](https://github.com/gitrdunhq/eedom/commit/70bac2a17f0a22293aada9f641a447f2ea3bba4b))
* security hardening — gitleaks PII, two-key release gate, SLSA attestation, SBOM, weekly dogfood ([9d32b49](https://github.com/gitrdunhq/eedom/commit/9d32b4912c815cdea41798426159b18fa1dcf169))
* separate security score from quality score — quality plugins are advisory, not merge-blocking ([0185d24](https://github.com/gitrdunhq/eedom/commit/0185d242544542866c408200da8d3167c2007ade))
* SLSA Level 3 build provenance for container images ([#29](https://github.com/gitrdunhq/eedom/issues/29)) ([#30](https://github.com/gitrdunhq/eedom/issues/30)) ([7338837](https://github.com/gitrdunhq/eedom/commit/7338837fc44190a02cc73e0daa31ceb16be0ecb2))
* validate SARIF line numbers against PR diff hunks + SMART inline comments ([#34](https://github.com/gitrdunhq/eedom/issues/34)) ([9d7fe8c](https://github.com/gitrdunhq/eedom/commit/9d7fe8c7d398f1b91bb2ef0113575460369cf9dd))


### Bug Fixes

* add .dogfood to manifest discovery skip list ([9ceb79e](https://github.com/gitrdunhq/eedom/commit/9ceb79eac59ff08fe321965304d84b33c3a282a6))
* add severity to unpinned dependency findings — critical for unversioned, high for ranges ([c14df35](https://github.com/gitrdunhq/eedom/commit/c14df357824d33e12b068334a20dc9d97309604d))
* address 3 Codex findings — cfn-nag returncode, stale cdk.out, JSON discovery (ICE + BLAZE + TURBO) ([72dc2b5](https://github.com/gitrdunhq/eedom/commit/72dc2b5a46df35be1bfe1a2a5108df508292ef88))
* address 7 Copilot findings — shell injection, missing perms, fork guard, SHA pinning, PR-context gates ([de144ad](https://github.com/gitrdunhq/eedom/commit/de144ad84556c2989f5b9d175d4acfae7a8751ec))
* auto-file issue on incomplete review — links to crashed PR and run ([863ef80](https://github.com/gitrdunhq/eedom/commit/863ef80db2c2545b8b34eff7acce1cd157134f79))
* blast-radius read-only filesystem crash + clamav exit-2 silent failure ([#33](https://github.com/gitrdunhq/eedom/issues/33)) ([b11d39f](https://github.com/gitrdunhq/eedom/commit/b11d39fe88e3565e1ec52dde43719f595f696892))
* container build — add LICENSE for hatchling + local eedom:latest tag ([d77fb15](https://github.com/gitrdunhq/eedom/commit/d77fb154e71dcfd1ef2257b65012918bfd88790f))
* Copilot request failure adds dom: needs-copilot label + comment ([7155646](https://github.com/gitrdunhq/eedom/commit/715564660c6b74b685a8c1cdc8cc249cfd34df90))
* correct pypi-publish action SHA pin — v1.14.0 ([0ef8145](https://github.com/gitrdunhq/eedom/commit/0ef81450882c05ab4d37933084ad51b7e8fdf530))
* cyclonedx-py CLI flags + non-blocking SBOM generation ([5116145](https://github.com/gitrdunhq/eedom/commit/5116145dd484ee8c31bb28d8010ef0dcc8654592))
* **docker:** copy README.md into build context for hatchling metadata ([2c5a19f](https://github.com/gitrdunhq/eedom/commit/2c5a19f3f8c64059a81a8beba0f055cc864570be))
* document intentional single-commit gitleaks scan ([5757470](https://github.com/gitrdunhq/eedom/commit/5757470e928d9b13c5ae045043f38a59e2715a51))
* exclude cdk.out/ from discovery + add .json to watch mode ([#81](https://github.com/gitrdunhq/eedom/issues/81)) ([14a1912](https://github.com/gitrdunhq/eedom/commit/14a1912c17761451efbf55c6fc9f0df98e3a2a12))
* expand DEFAULT_PATTERNS with build artifacts, IDE, agent state dirs ([#85](https://github.com/gitrdunhq/eedom/issues/85)) ([1ee1def](https://github.com/gitrdunhq/eedom/commit/1ee1def4c75eb836b46f5f52a010800088e2cfca))
* fail-closed GATEKEEPER — emit plugin errors in SARIF + block on crashed scanners ([1dc84fe](https://github.com/gitrdunhq/eedom/commit/1dc84fe058e352a1323cbdfaf95ed7d3f9cb232e))
* fail-open crash threshold — dom: incomplete when 3+ plugins crash ([94380f6](https://github.com/gitrdunhq/eedom/commit/94380f63a30060f0bacb48fcfd058b7dfe076eaf))
* include .j2 templates in wheel — artifacts config for hatchling ([6306d54](https://github.com/gitrdunhq/eedom/commit/6306d543d7eef4aee9a83f2219aa5e8e8beb1b0b))
* include Jinja2 templates in wheel + gitleaks custom config support ([#31](https://github.com/gitrdunhq/eedom/issues/31)) ([d253185](https://github.com/gitrdunhq/eedom/commit/d253185aa0b165cdfe40ec59d52656633801c169))
* move all GH Actions interpolations to env blocks — eliminate shell injection ([1987dc5](https://github.com/gitrdunhq/eedom/commit/1987dc594f57bd83488e5e3557853d7d061a5881))
* pin GitHub Actions to full commit SHAs — org policy requires it ([b7f8329](https://github.com/gitrdunhq/eedom/commit/b7f83292c11837f113d137de542104a163ca4812))
* remove --add-reviewer [@copilot](https://github.com/copilot) from CI — GITHUB_TOKEN lacks permission ([af79ebd](https://github.com/gitrdunhq/eedom/commit/af79ebd29ccf4abac92bf35324669231fd9e70a3))
* render report sections security-first by category priority ([#89](https://github.com/gitrdunhq/eedom/issues/89)) ([644492e](https://github.com/gitrdunhq/eedom/commit/644492e978159fcec03ab10731e53e221bf1c0a6))
* repair double-word stutters from admission rename ([#6](https://github.com/gitrdunhq/eedom/issues/6)) ([f098504](https://github.com/gitrdunhq/eedom/commit/f09850471ca32d4f270e06bee22a3bdb49cd6601))
* resolve all 14 dogfood findings ([#22](https://github.com/gitrdunhq/eedom/issues/22)) ([d1a19c3](https://github.com/gitrdunhq/eedom/commit/d1a19c367660016d80bedd432ca1519d5ce2a12b))
* run GATEKEEPER on all PRs + fix broken markdown table ([ba7c52d](https://github.com/gitrdunhq/eedom/commit/ba7c52dd09b621631ba167fc4b1719eb16431bf1))
* scanner runners fail-LOUD on bad JSON + CI workflow hardening ([7870e32](https://github.com/gitrdunhq/eedom/commit/7870e32c99914cfb9ec0297b8d5b3b3d9bf67a68))
* semgrep subprocess-no-timeout false positives + 3 new rules ([#13](https://github.com/gitrdunhq/eedom/issues/13)) ([9872a3d](https://github.com/gitrdunhq/eedom/commit/9872a3dbf007f38ac1006db493c63dc6df9475f3))
* top 10 dogfood findings — eedom self-heals ([#8](https://github.com/gitrdunhq/eedom/issues/8)) ([9b7a839](https://github.com/gitrdunhq/eedom/commit/9b7a8398410a685b30c75d2cdc4b72f78b81b7d8))
* try requesting Copilot review, fail silently if token lacks permission ([12860f8](https://github.com/gitrdunhq/eedom/commit/12860f8be0aa0beee63ab4c58e0ddb465f2ec332))


### Documentation

* explain telemetry value — eedom dogfoods itself, human-triaged bug fixing in realtime ([583c487](https://github.com/gitrdunhq/eedom/commit/583c48701e100f6701ae986788ba2a039dc20e07))
* plugin prose — security (gates merges) and quality (advisory) with severity tables ([f1e0874](https://github.com/gitrdunhq/eedom/commit/f1e0874ff2bcdaa90cacd8f8293cce0f170b1c17))
* rewrite elevator pitch — cognitive burden reduction for engineering teams ([79f3144](https://github.com/gitrdunhq/eedom/commit/79f3144578608b2e3f16f4abb71fe7e3c28c5488))
* telemetry modes — community (contribute back) vs self-heal (internal only) ([aaf3200](https://github.com/gitrdunhq/eedom/commit/aaf32001e474652a46b0c382207b1ee0228f70ee))
* update plugin counts to 18 + add capability matrix reference ([a202c17](https://github.com/gitrdunhq/eedom/commit/a202c1703e56e28207e246ac3c3c2825e157c18b))

## [0.2.2](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.1...eedom-v0.2.2) (2026-04-27)


### Features

* add DPS-12 property-based testing standard — 14 domains, formal property types ([#39](https://github.com/gitrdunhq/eedom/issues/39)) ([d99ca66](https://github.com/gitrdunhq/eedom/commit/d99ca669e3a1f43e18b876b6b75e1a581e2afa43))
* cfn-nag + cdk-nag plugins — AWS CloudFormation/CDK security scanning (STORM + HAWK) ([6ca9943](https://github.com/gitrdunhq/eedom/commit/6ca9943fdeed2305803f5eb32a02e61da154f33f))
* eedom v1.2.0 — clean scanner repo, split from securePackages ([acf67fc](https://github.com/gitrdunhq/eedom/commit/acf67fc587538e002363a6dc79dc27214fa58a32))
* mypy/pyright plugin + enforce container-only test execution ([#41](https://github.com/gitrdunhq/eedom/issues/41)) ([7e85a2d](https://github.com/gitrdunhq/eedom/commit/7e85a2d59223052a333bbb98bafbff67b17167ad)), closes [#37](https://github.com/gitrdunhq/eedom/issues/37)
* native PR review posting — inline comments from SARIF ([#25](https://github.com/gitrdunhq/eedom/issues/25)) ([70bac2a](https://github.com/gitrdunhq/eedom/commit/70bac2a17f0a22293aada9f641a447f2ea3bba4b))
* security hardening — gitleaks PII, two-key release gate, SLSA attestation, SBOM, weekly dogfood ([9d32b49](https://github.com/gitrdunhq/eedom/commit/9d32b4912c815cdea41798426159b18fa1dcf169))
* separate security score from quality score — quality plugins are advisory, not merge-blocking ([0185d24](https://github.com/gitrdunhq/eedom/commit/0185d242544542866c408200da8d3167c2007ade))
* SLSA Level 3 build provenance for container images ([#29](https://github.com/gitrdunhq/eedom/issues/29)) ([#30](https://github.com/gitrdunhq/eedom/issues/30)) ([7338837](https://github.com/gitrdunhq/eedom/commit/7338837fc44190a02cc73e0daa31ceb16be0ecb2))
* validate SARIF line numbers against PR diff hunks + SMART inline comments ([#34](https://github.com/gitrdunhq/eedom/issues/34)) ([9d7fe8c](https://github.com/gitrdunhq/eedom/commit/9d7fe8c7d398f1b91bb2ef0113575460369cf9dd))


### Bug Fixes

* add .dogfood to manifest discovery skip list ([9ceb79e](https://github.com/gitrdunhq/eedom/commit/9ceb79eac59ff08fe321965304d84b33c3a282a6))
* add severity to unpinned dependency findings — critical for unversioned, high for ranges ([c14df35](https://github.com/gitrdunhq/eedom/commit/c14df357824d33e12b068334a20dc9d97309604d))
* address 3 Codex findings — cfn-nag returncode, stale cdk.out, JSON discovery (ICE + BLAZE + TURBO) ([72dc2b5](https://github.com/gitrdunhq/eedom/commit/72dc2b5a46df35be1bfe1a2a5108df508292ef88))
* address 7 Copilot findings — shell injection, missing perms, fork guard, SHA pinning, PR-context gates ([de144ad](https://github.com/gitrdunhq/eedom/commit/de144ad84556c2989f5b9d175d4acfae7a8751ec))
* auto-file issue on incomplete review — links to crashed PR and run ([863ef80](https://github.com/gitrdunhq/eedom/commit/863ef80db2c2545b8b34eff7acce1cd157134f79))
* blast-radius read-only filesystem crash + clamav exit-2 silent failure ([#33](https://github.com/gitrdunhq/eedom/issues/33)) ([b11d39f](https://github.com/gitrdunhq/eedom/commit/b11d39fe88e3565e1ec52dde43719f595f696892))
* container build — add LICENSE for hatchling + local eedom:latest tag ([d77fb15](https://github.com/gitrdunhq/eedom/commit/d77fb154e71dcfd1ef2257b65012918bfd88790f))
* Copilot request failure adds dom: needs-copilot label + comment ([7155646](https://github.com/gitrdunhq/eedom/commit/715564660c6b74b685a8c1cdc8cc249cfd34df90))
* correct pypi-publish action SHA pin — v1.14.0 ([0ef8145](https://github.com/gitrdunhq/eedom/commit/0ef81450882c05ab4d37933084ad51b7e8fdf530))
* **docker:** copy README.md into build context for hatchling metadata ([2c5a19f](https://github.com/gitrdunhq/eedom/commit/2c5a19f3f8c64059a81a8beba0f055cc864570be))
* document intentional single-commit gitleaks scan ([5757470](https://github.com/gitrdunhq/eedom/commit/5757470e928d9b13c5ae045043f38a59e2715a51))
* exclude cdk.out/ from discovery + add .json to watch mode ([#81](https://github.com/gitrdunhq/eedom/issues/81)) ([14a1912](https://github.com/gitrdunhq/eedom/commit/14a1912c17761451efbf55c6fc9f0df98e3a2a12))
* expand DEFAULT_PATTERNS with build artifacts, IDE, agent state dirs ([#85](https://github.com/gitrdunhq/eedom/issues/85)) ([1ee1def](https://github.com/gitrdunhq/eedom/commit/1ee1def4c75eb836b46f5f52a010800088e2cfca))
* fail-closed GATEKEEPER — emit plugin errors in SARIF + block on crashed scanners ([1dc84fe](https://github.com/gitrdunhq/eedom/commit/1dc84fe058e352a1323cbdfaf95ed7d3f9cb232e))
* fail-open crash threshold — dom: incomplete when 3+ plugins crash ([94380f6](https://github.com/gitrdunhq/eedom/commit/94380f63a30060f0bacb48fcfd058b7dfe076eaf))
* include .j2 templates in wheel — artifacts config for hatchling ([6306d54](https://github.com/gitrdunhq/eedom/commit/6306d543d7eef4aee9a83f2219aa5e8e8beb1b0b))
* include Jinja2 templates in wheel + gitleaks custom config support ([#31](https://github.com/gitrdunhq/eedom/issues/31)) ([d253185](https://github.com/gitrdunhq/eedom/commit/d253185aa0b165cdfe40ec59d52656633801c169))
* move all GH Actions interpolations to env blocks — eliminate shell injection ([1987dc5](https://github.com/gitrdunhq/eedom/commit/1987dc594f57bd83488e5e3557853d7d061a5881))
* pin GitHub Actions to full commit SHAs — org policy requires it ([b7f8329](https://github.com/gitrdunhq/eedom/commit/b7f83292c11837f113d137de542104a163ca4812))
* remove --add-reviewer [@copilot](https://github.com/copilot) from CI — GITHUB_TOKEN lacks permission ([af79ebd](https://github.com/gitrdunhq/eedom/commit/af79ebd29ccf4abac92bf35324669231fd9e70a3))
* render report sections security-first by category priority ([#89](https://github.com/gitrdunhq/eedom/issues/89)) ([644492e](https://github.com/gitrdunhq/eedom/commit/644492e978159fcec03ab10731e53e221bf1c0a6))
* repair double-word stutters from admission rename ([#6](https://github.com/gitrdunhq/eedom/issues/6)) ([f098504](https://github.com/gitrdunhq/eedom/commit/f09850471ca32d4f270e06bee22a3bdb49cd6601))
* resolve all 14 dogfood findings ([#22](https://github.com/gitrdunhq/eedom/issues/22)) ([d1a19c3](https://github.com/gitrdunhq/eedom/commit/d1a19c367660016d80bedd432ca1519d5ce2a12b))
* run GATEKEEPER on all PRs + fix broken markdown table ([ba7c52d](https://github.com/gitrdunhq/eedom/commit/ba7c52dd09b621631ba167fc4b1719eb16431bf1))
* scanner runners fail-LOUD on bad JSON + CI workflow hardening ([7870e32](https://github.com/gitrdunhq/eedom/commit/7870e32c99914cfb9ec0297b8d5b3b3d9bf67a68))
* semgrep subprocess-no-timeout false positives + 3 new rules ([#13](https://github.com/gitrdunhq/eedom/issues/13)) ([9872a3d](https://github.com/gitrdunhq/eedom/commit/9872a3dbf007f38ac1006db493c63dc6df9475f3))
* top 10 dogfood findings — eedom self-heals ([#8](https://github.com/gitrdunhq/eedom/issues/8)) ([9b7a839](https://github.com/gitrdunhq/eedom/commit/9b7a8398410a685b30c75d2cdc4b72f78b81b7d8))
* try requesting Copilot review, fail silently if token lacks permission ([12860f8](https://github.com/gitrdunhq/eedom/commit/12860f8be0aa0beee63ab4c58e0ddb465f2ec332))


### Documentation

* explain telemetry value — eedom dogfoods itself, human-triaged bug fixing in realtime ([583c487](https://github.com/gitrdunhq/eedom/commit/583c48701e100f6701ae986788ba2a039dc20e07))
* plugin prose — security (gates merges) and quality (advisory) with severity tables ([f1e0874](https://github.com/gitrdunhq/eedom/commit/f1e0874ff2bcdaa90cacd8f8293cce0f170b1c17))
* rewrite elevator pitch — cognitive burden reduction for engineering teams ([79f3144](https://github.com/gitrdunhq/eedom/commit/79f3144578608b2e3f16f4abb71fe7e3c28c5488))
* telemetry modes — community (contribute back) vs self-heal (internal only) ([aaf3200](https://github.com/gitrdunhq/eedom/commit/aaf32001e474652a46b0c382207b1ee0228f70ee))
* update plugin counts to 18 + add capability matrix reference ([a202c17](https://github.com/gitrdunhq/eedom/commit/a202c1703e56e28207e246ac3c3c2825e157c18b))

## [0.2.1](https://github.com/gitrdunhq/eedom/compare/eedom-v0.2.0...eedom-v0.2.1) (2026-04-27)


### Features

* add DPS-12 property-based testing standard — 14 domains, formal property types ([#39](https://github.com/gitrdunhq/eedom/issues/39)) ([d99ca66](https://github.com/gitrdunhq/eedom/commit/d99ca669e3a1f43e18b876b6b75e1a581e2afa43))
* cfn-nag + cdk-nag plugins — AWS CloudFormation/CDK security scanning (STORM + HAWK) ([6ca9943](https://github.com/gitrdunhq/eedom/commit/6ca9943fdeed2305803f5eb32a02e61da154f33f))
* eedom v1.2.0 — clean scanner repo, split from securePackages ([acf67fc](https://github.com/gitrdunhq/eedom/commit/acf67fc587538e002363a6dc79dc27214fa58a32))
* mypy/pyright plugin + enforce container-only test execution ([#41](https://github.com/gitrdunhq/eedom/issues/41)) ([7e85a2d](https://github.com/gitrdunhq/eedom/commit/7e85a2d59223052a333bbb98bafbff67b17167ad)), closes [#37](https://github.com/gitrdunhq/eedom/issues/37)
* native PR review posting — inline comments from SARIF ([#25](https://github.com/gitrdunhq/eedom/issues/25)) ([70bac2a](https://github.com/gitrdunhq/eedom/commit/70bac2a17f0a22293aada9f641a447f2ea3bba4b))
* security hardening — gitleaks PII, two-key release gate, SLSA attestation, SBOM, weekly dogfood ([9d32b49](https://github.com/gitrdunhq/eedom/commit/9d32b4912c815cdea41798426159b18fa1dcf169))
* separate security score from quality score — quality plugins are advisory, not merge-blocking ([0185d24](https://github.com/gitrdunhq/eedom/commit/0185d242544542866c408200da8d3167c2007ade))
* SLSA Level 3 build provenance for container images ([#29](https://github.com/gitrdunhq/eedom/issues/29)) ([#30](https://github.com/gitrdunhq/eedom/issues/30)) ([7338837](https://github.com/gitrdunhq/eedom/commit/7338837fc44190a02cc73e0daa31ceb16be0ecb2))
* validate SARIF line numbers against PR diff hunks + SMART inline comments ([#34](https://github.com/gitrdunhq/eedom/issues/34)) ([9d7fe8c](https://github.com/gitrdunhq/eedom/commit/9d7fe8c7d398f1b91bb2ef0113575460369cf9dd))


### Bug Fixes

* add .dogfood to manifest discovery skip list ([9ceb79e](https://github.com/gitrdunhq/eedom/commit/9ceb79eac59ff08fe321965304d84b33c3a282a6))
* add severity to unpinned dependency findings — critical for unversioned, high for ranges ([c14df35](https://github.com/gitrdunhq/eedom/commit/c14df357824d33e12b068334a20dc9d97309604d))
* address 3 Codex findings — cfn-nag returncode, stale cdk.out, JSON discovery (ICE + BLAZE + TURBO) ([72dc2b5](https://github.com/gitrdunhq/eedom/commit/72dc2b5a46df35be1bfe1a2a5108df508292ef88))
* address 7 Copilot findings — shell injection, missing perms, fork guard, SHA pinning, PR-context gates ([de144ad](https://github.com/gitrdunhq/eedom/commit/de144ad84556c2989f5b9d175d4acfae7a8751ec))
* auto-file issue on incomplete review — links to crashed PR and run ([863ef80](https://github.com/gitrdunhq/eedom/commit/863ef80db2c2545b8b34eff7acce1cd157134f79))
* blast-radius read-only filesystem crash + clamav exit-2 silent failure ([#33](https://github.com/gitrdunhq/eedom/issues/33)) ([b11d39f](https://github.com/gitrdunhq/eedom/commit/b11d39fe88e3565e1ec52dde43719f595f696892))
* container build — add LICENSE for hatchling + local eedom:latest tag ([d77fb15](https://github.com/gitrdunhq/eedom/commit/d77fb154e71dcfd1ef2257b65012918bfd88790f))
* Copilot request failure adds dom: needs-copilot label + comment ([7155646](https://github.com/gitrdunhq/eedom/commit/715564660c6b74b685a8c1cdc8cc249cfd34df90))
* **docker:** copy README.md into build context for hatchling metadata ([2c5a19f](https://github.com/gitrdunhq/eedom/commit/2c5a19f3f8c64059a81a8beba0f055cc864570be))
* document intentional single-commit gitleaks scan ([5757470](https://github.com/gitrdunhq/eedom/commit/5757470e928d9b13c5ae045043f38a59e2715a51))
* exclude cdk.out/ from discovery + add .json to watch mode ([#81](https://github.com/gitrdunhq/eedom/issues/81)) ([14a1912](https://github.com/gitrdunhq/eedom/commit/14a1912c17761451efbf55c6fc9f0df98e3a2a12))
* expand DEFAULT_PATTERNS with build artifacts, IDE, agent state dirs ([#85](https://github.com/gitrdunhq/eedom/issues/85)) ([1ee1def](https://github.com/gitrdunhq/eedom/commit/1ee1def4c75eb836b46f5f52a010800088e2cfca))
* fail-closed GATEKEEPER — emit plugin errors in SARIF + block on crashed scanners ([1dc84fe](https://github.com/gitrdunhq/eedom/commit/1dc84fe058e352a1323cbdfaf95ed7d3f9cb232e))
* fail-open crash threshold — dom: incomplete when 3+ plugins crash ([94380f6](https://github.com/gitrdunhq/eedom/commit/94380f63a30060f0bacb48fcfd058b7dfe076eaf))
* include .j2 templates in wheel — artifacts config for hatchling ([6306d54](https://github.com/gitrdunhq/eedom/commit/6306d543d7eef4aee9a83f2219aa5e8e8beb1b0b))
* include Jinja2 templates in wheel + gitleaks custom config support ([#31](https://github.com/gitrdunhq/eedom/issues/31)) ([d253185](https://github.com/gitrdunhq/eedom/commit/d253185aa0b165cdfe40ec59d52656633801c169))
* move all GH Actions interpolations to env blocks — eliminate shell injection ([1987dc5](https://github.com/gitrdunhq/eedom/commit/1987dc594f57bd83488e5e3557853d7d061a5881))
* pin GitHub Actions to full commit SHAs — org policy requires it ([b7f8329](https://github.com/gitrdunhq/eedom/commit/b7f83292c11837f113d137de542104a163ca4812))
* remove --add-reviewer [@copilot](https://github.com/copilot) from CI — GITHUB_TOKEN lacks permission ([af79ebd](https://github.com/gitrdunhq/eedom/commit/af79ebd29ccf4abac92bf35324669231fd9e70a3))
* render report sections security-first by category priority ([#89](https://github.com/gitrdunhq/eedom/issues/89)) ([644492e](https://github.com/gitrdunhq/eedom/commit/644492e978159fcec03ab10731e53e221bf1c0a6))
* repair double-word stutters from admission rename ([#6](https://github.com/gitrdunhq/eedom/issues/6)) ([f098504](https://github.com/gitrdunhq/eedom/commit/f09850471ca32d4f270e06bee22a3bdb49cd6601))
* resolve all 14 dogfood findings ([#22](https://github.com/gitrdunhq/eedom/issues/22)) ([d1a19c3](https://github.com/gitrdunhq/eedom/commit/d1a19c367660016d80bedd432ca1519d5ce2a12b))
* run GATEKEEPER on all PRs + fix broken markdown table ([ba7c52d](https://github.com/gitrdunhq/eedom/commit/ba7c52dd09b621631ba167fc4b1719eb16431bf1))
* scanner runners fail-LOUD on bad JSON + CI workflow hardening ([7870e32](https://github.com/gitrdunhq/eedom/commit/7870e32c99914cfb9ec0297b8d5b3b3d9bf67a68))
* semgrep subprocess-no-timeout false positives + 3 new rules ([#13](https://github.com/gitrdunhq/eedom/issues/13)) ([9872a3d](https://github.com/gitrdunhq/eedom/commit/9872a3dbf007f38ac1006db493c63dc6df9475f3))
* top 10 dogfood findings — eedom self-heals ([#8](https://github.com/gitrdunhq/eedom/issues/8)) ([9b7a839](https://github.com/gitrdunhq/eedom/commit/9b7a8398410a685b30c75d2cdc4b72f78b81b7d8))
* try requesting Copilot review, fail silently if token lacks permission ([12860f8](https://github.com/gitrdunhq/eedom/commit/12860f8be0aa0beee63ab4c58e0ddb465f2ec332))


### Documentation

* explain telemetry value — eedom dogfoods itself, human-triaged bug fixing in realtime ([583c487](https://github.com/gitrdunhq/eedom/commit/583c48701e100f6701ae986788ba2a039dc20e07))
* plugin prose — security (gates merges) and quality (advisory) with severity tables ([f1e0874](https://github.com/gitrdunhq/eedom/commit/f1e0874ff2bcdaa90cacd8f8293cce0f170b1c17))
* rewrite elevator pitch — cognitive burden reduction for engineering teams ([79f3144](https://github.com/gitrdunhq/eedom/commit/79f3144578608b2e3f16f4abb71fe7e3c28c5488))
* telemetry modes — community (contribute back) vs self-heal (internal only) ([aaf3200](https://github.com/gitrdunhq/eedom/commit/aaf32001e474652a46b0c382207b1ee0228f70ee))
* update plugin counts to 18 + add capability matrix reference ([a202c17](https://github.com/gitrdunhq/eedom/commit/a202c1703e56e28207e246ac3c3c2825e157c18b))

## [Unreleased]

### Added

**GATEKEEPER Copilot Agent — reactive PR review**
- New `src/eedom/agent/` module: GitHub Copilot Agent that wraps the existing review pipeline for reactive PR review
- 8-tool scanning suite (all deterministic, no LLM in the scanning pipeline):
  - Syft (SBOM generation, 18 ecosystems)
  - OSV-Scanner (CVE/GHSA database lookup)
  - Trivy (vulnerability scanning)
  - ScanCode (license analysis)
  - OPA (deterministic policy enforcement, 6 rules)
  - Semgrep (AST pattern matching, dynamic rulesets + pinned rules + org custom rules)
  - PMD CPD (token-based copy-paste detection)
  - kube-linter (Kubernetes/Helm manifest validation)
- Multi-ecosystem dependency support via SBOM path: npm, Cargo, Go, Ruby, Maven, NuGet, Dart, PHP, Elixir, Swift, CocoaPods (18 total)
- Configurable enforcement modes: `block` (fail build), `warn` (comment only), `log` (silent)
- GitHub Action workflow (`.github/workflows/gatekeeper.yml`) for self-hosted runners
- Custom Semgrep org rules (`policies/semgrep/org-code-smells.yaml`)
- Dynamic Semgrep ruleset selection based on file types in the PR diff
- Pinned Semgrep rules from local `semgrep-rules` repo clone (supply chain protection)
- 8-dimension task-fit rubric embedded in agent system prompt (NECESSITY, MINIMALITY, MAINTENANCE, SECURITY, EXPOSURE, BLAST_RADIUS, ALTERNATIVES, BEHAVIORAL)
- Dependency tree summary with direct/transitive/shared package breakdown
- Per-package PR comments with grouped policy verdicts
- Stress test scripts (`scripts/gauntlet.py`) tested against 12 real PRs

**Plugin architecture — 15 plugins with auto-discovery**
- `ScannerPlugin` ABC with `run()`, `can_run()`, `render()` contract
- `PluginRegistry` with `discover_plugins()` auto-discovery from `plugins/` directory
- `eedom review` CLI command — runs all plugins via registry
- `eedom plugins` CLI command — lists registered plugins
- Blast radius plugin: AST-to-SQLite code graph, 8 SQL checks
- Supply chain plugin: unpinned deps, lockfile integrity, floating version detection
- ClamAV plugin: malware/virus scanning
- Gitleaks plugin: secret/credential detection, 800+ patterns, secrets never in output
- Complexity plugin: Lizard + Radon cyclomatic complexity and maintainability index
- cspell plugin: code-aware spell checking (en-CA, 11 dictionaries)
- ls-lint plugin: file naming convention enforcement
- Centralized error codes (`ErrorCode` enum, uniform across all plugins and runners)
- 14 Semgrep coding standards rules derived from CODING-STANDARDS.md
- Jinja2 template renderer with verdict logic (BLOCKED / INCOMPLETE / WARNINGS / ALL CLEAR)

**Architecture decisions**
- ADR-001: Agent module as separate presentation-tier entry point
- ADR-002: Agent IS the task-fit LLM (rubric in system prompt, no separate call)
- ADR-003: GitHub Copilot SDK for agent framework
- ADR-004: Semgrep as agent tool, not Scanner ABC subclass

**Repo best practices**
- LICENSE (PolyForm Shield 1.0.0)
- THIRD-PARTY-NOTICES.md listing all 14 upstream scanner tools and their licenses
- SECURITY.md (vulnerability reporting policy)
- CODEOWNERS
- `.editorconfig`
- `src/eedom/py.typed` (PEP 561)
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/ISSUE_TEMPLATE/bug_report.md`, `see_something.md`
- release-please GitHub Action for automated CHANGELOG and version management

### Changed

- License changed from MIT to PolyForm Shield 1.0.0
- `ARCHITECTURE.md` updated with agent module in presentation tier
- `CLAUDE.md` updated with GATEKEEPER section and GitHub templates guidance
- `.gitignore` reorganized by category, added `.DS_Store`, `.zip`
- `Dockerfile` extended with Semgrep binary + agent entry point comment
- Planning artifacts (`TASKS.md`, `VALIDATE.md`, `VALIDATE-v2.md`) moved to `docs/`

### Security

- Reject detection uses structured OPA verdicts, not LLM prose parsing (prevents prompt injection bypass of block mode)
- Diff content wrapped in `<diff>` XML tags with system prompt marking it as untrusted data
- Exception messages replaced with stable error codes — no credential leakage in PR comments
- Path traversal guard on Semgrep `--include` file paths
- Input validation on `check_package` name/version (regex allowlist)
- `SecretStr` for `github_token` in `AgentSettings`

## [0.1.0] - 2026-04-23

### Added

**Phase 0 — Jenkins PoC foundation**
- `ReviewPipeline` entry point: evaluates dependency changes on PRs via Jenkins
- CLI (`src/eedom/cli/main.py`) with `monitor` and `advise` operating modes
- Jenkins shared library (`jenkins/vars/dependencyReview.groovy`) with `withEnv`-based parameter passing

**Scanners**
- `OsvScanner` — OSV-Scanner CVE detection; non-recursive invocation to avoid recursive scanning on monorepos
- `TrivyScanner` — Trivy vulnerability scan with severity normalization
- `SyftScanner` — SBOM generation (CycloneDX JSON); used for dependency diffing and transitive count
- `ScanCodeScanner` — ScanCode license analysis

**Core pipeline**
- `ScanOrchestrator` with `ThreadPoolExecutor` for parallel scanner execution (4 scanners × 60s budget)
- Wall-clock pipeline timeout enforcement (300s cap) with per-package break logic
- `DependencyDiffDetector` — unified-diff parsing via `extract_file_content_from_diff()`; supports `requirements.txt` and `pyproject.toml` formats
- SBOM-based ecosystem-agnostic dependency diffing (`sbom_diff.py`) via Syft; detects added/removed/upgraded packages across any package ecosystem
- `FindingNormalizer` — cross-scanner deduplication; highest severity wins on disagreement; dedup key includes finding category to prevent non-vuln collapses

**Policy**
- OPA `policy.rego` policy with deny rules for critical CVEs, license violations, package age, and transitive dependency depth
- `package_metadata` populated from PyPI client (`first_published_date`) and Syft SBOM (`transitive_dep_count`) so age and depth rules fire
- CVSS base score parsing with vector heuristic fallback — no more silent `info` rating for untagged vulns

**Evidence and audit**
- `EvidenceStore` — per-run artifact storage keyed by commit SHA + timestamp (not random UUID), ensuring reproducible lookups
- Parquet audit lake (`parquet_writer.py`) — append-only columnar evidence store; queryable via DuckDB or any Parquet reader
- Decision memo assembly (`memo.py`) with structured rationale for PR comments

**Org intelligence**
- `CatalogClient` — org package catalog with semantic search for alternative package suggestions
- `TaskfitValidator` — LLM-based semantic fit check with structured role-separation prompting (system/user) to prevent prompt injection from PyPI metadata fields
- Input sanitization for all PyPI-sourced fields before LLM prompt construction

**Data layer**
- `DecisionRepository` (PostgreSQL) and `NullRepository` (in-memory) sharing a common `RepositoryProtocol`
- DB DSN password masking via `_safe_dsn()` — no plaintext credentials in logs
- `db_dsn` typed as `pydantic.SecretStr` to prevent accidental string serialization of credentials

**Configuration**
- All timeouts configurable via `ReviewConfig`; no hardcoded values in business logic
- Startup validation fails fast on missing critical config fields

### Fixed

**Dogfood bugs (caught post-initial-commit)**
- `OsvScanner` was invoked with `--recursive` flag, causing it to re-scan nested `node_modules` and virtualenvs; removed flag and scoped scan to project root
- OPA reserved word collision: renamed `input.package` to `input.pkg` in `policy.rego` (reserved word in Rego)
- DB connection timeout mis-configured as string instead of int; `psycopg2` rejected the value silently and fell back to no timeout

**Review Pass 1 — 15 critical/high findings (all fixed)**
- `_parse_changes` was calling parsers with hardcoded empty strings; `diff_text` was received but never forwarded — pipeline always returned "No dependency changes detected" regardless of PR content (F-001)
- `ScanOrchestrator` raised `TypeError` on every run due to unrecognised `individual_timeout` kwarg (F-002)
- `OsvScanner` raised `TypeError`: constructor does not accept `evidence_dir` (F-003)
- `TrivyScanner` raised `TypeError`: no custom `__init__`, no kwargs accepted (F-004)
- Scanner orchestration was inside the per-package for-loop; 50 packages → 50× full scanner execution; hoisted above loop (F-005)
- `sys.exit(0)` was unconditional; Jenkins always saw success even on crash; now exits 1 on unexpected errors (F-006)
- Pipeline timeout was loaded from config but never enforced; wall-clock guard added (F-007)
- Jenkins shell injection: `team`, `operatingMode`, `prUrl` were string-interpolated into shell command; replaced with `withEnv` (F-008)
- Full PostgreSQL DSN with plaintext password logged at INFO/ERROR level; masked with `_safe_dsn()` (F-009)
- OSV CVSS severity fallback was `pass`; all untagged vulns rated `info`, bypassing OPA deny rules; score parsing added (F-010)
- Scanner execution was sequential; parallelised with `ThreadPoolExecutor` (F-011)
- OPA `package_age` and `transitive_count` rules were permanently bypassed due to missing metadata keys (F-012)
- LLM prompt injection: PyPI name/description concatenated directly into prompt; structured messages + sanitization applied (F-013)
- `str`/`Path` type mismatch on `evidence_dir`; `.mkdir()` raised `AttributeError`; `Path()` coercion added (F-014)
- `core/orchestrator.py` imported private `_make_failed_result` from `data/scanners/base.py` (tier inversion); moved to `ScanResult` factory class methods in `core/models.py` (F-015)

**Review Pass 2 — regressions caught mid-review**
- `EvidenceStore.store_file()` missing path traversal guard on `artifact_name`; `..` traversal now rejected
- Version comparison in `diff.py` used lexicographic ordering (`"1.9" > "1.10"`); replaced with `packaging.version.Version`
- Config failure showed misleading "No dependency changes detected" message; now shows explicit config error

### Security

- Jenkins shell injection via string interpolation → `withEnv` parameter passing (F-008)
- Plaintext DSN passwords in logs → `_safe_dsn()` masking (F-009)
- Path traversal in `EvidenceStore` via unvalidated `artifact_name` → guard added (F-022)
- LLM prompt injection from PyPI metadata fields → structured role separation + sanitization (F-013)
- LLM API key stored as `str` → `pydantic.SecretStr` (F-021)
- `db_dsn` exposed as plain string → `SecretStr` in `ReviewConfig`

### Changed

- Pipeline logic extracted from CLI presentation layer into `ReviewPipeline` in `core/pipeline.py`; `main.py` is now a thin adapter (F-024)
- Evidence keyed by commit SHA + timestamp instead of random UUID — enables deterministic replay and audit correlation
- Scanner result factory functions moved from `data/scanners/base.py` to `core/models.py` to fix tier inversion
