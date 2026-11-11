# Changelog

All notable changes to Ward are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Ward uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- High-severity `exposed-git-config` web exposure rule (`exposure.yaml`) with a dedicated `web-exposure-scanner`: probes `<origin>/.git/config` over GET with no redirects and a capped response body, uses a per-host cached `/.git/ward-<nonce>.probe` soft-404 baseline, requires raw `[core]` + `repositoryformatversion` lines, and suppresses HTML/login pages and normalized probe-identical replies without letting probe failures hide strict raw hits.
- `web.origins` / `web.timeout` config section; scanning an `http(s)` target auto-probes its origin (and the opposite scheme).
- `regex-scoped` pattern type: suppresses rule findings that fall inside a brace-delimited scope block (e.g. a `Route::middleware()->group()` closure), eliminating false positives for `AUTH-001` and `AUTH-005`.

### Fixed
- `AUTH-001` and `AUTH-005` no longer flag routes defined inside a middleware group as unprotected.

---

## [0.4.0] - 2026-02-19

### Added
- SARIF output format for GitHub Code Scanning integration.
- CI/CD integration guide (`docs/ci-integration.md`).
- Docker support documentation.

### Changed
- Minimum Go version bumped to 1.24+.

### Fixed
- Various SARIF spec compliance fixes.

---

## [0.3.2] - 2026-02-19

### Added
- Core scanning orchestrator.
- YAML rules-based scanner with default security rules.
- MIT license.

### Fixed
- Baseline management improvements.

---

## [0.3.1] - 2026-02-19

### Fixed
- Version resolution from Go build info when installed via `go install`.

---

## [0.3.0] - 2026-02-19

### Added
- Core CLI commands and configuration management.
- Terminal UI (TUI) built on Bubble Tea with scan and results views.
- SARIF and Markdown report output.
- Environment file scanner (`.env` misconfigurations).
- Custom YAML rules engine.
- HTML report generation with categorized findings.

---

[Unreleased]: https://github.com/eljakani/ward/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/eljakani/ward/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/eljakani/ward/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/eljakani/ward/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/eljakani/ward/releases/tag/v0.3.0
