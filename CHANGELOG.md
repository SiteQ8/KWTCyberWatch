# Changelog

All notable changes to KWTCyberWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-09-24

### Added
- **Browser-native detection engine** (`demo/engine.js`): a JavaScript port of the phishing
  detector, brand monitor and domain analyzer — registrable-domain parsing, IDN/punycode,
  mixed-script and Arabic handling, confusable skeletons, leet folding, technique detection,
  brand ranking, scoring and the permutation generator. `scripts/export_engine_data.py` generates
  `demo/engine-data.js` from the Python tables and `tests/test_js_engine.py` asserts verdict
  parity on a 90-domain corpus (fails when the generated file is stale).
- **Real GitHub Pages demo** (`demo/app.js`): the dashboard no longer uses sample data. It
  streams the live CertStream WebSocket feed and scores every certificate, scans with the local
  engine plus live DNS-over-HTTPS / crt.sh / RDAP / URLhaus enrichment, hunts typosquats by
  resolving generated permutations and records sightings, keeps alerts with a full triage
  lifecycle, and computes dashboard/analytics figures from what it has actually seen.
  Everything persists in IndexedDB; workspaces can be exported and imported as JSON; alerts export
  as CSV and STIX 2.1 bundles built in the browser; desktop notifications are optional.
- Settings for feed keywords, allowlist and custom brand profiles rebuild the browser engine
  immediately.

- **Redesigned look and feel**: a hero landing page with live engine figures, SVG icon
  navigation, light/dark themes (toggle in the top bar, remembered per browser), a risk gauge on
  scan results, refreshed cards, tables, feed rows and toasts, an off-canvas sidebar and tuned
  layouts for phones, plus keyboard shortcuts (`/` focuses the scanner, `g` then a letter jumps
  between views).
- **Analyst tooling** (`demo/features.js`): a command palette (`Ctrl/Cmd+K`) that scans, hunts,
  investigates or allowlists any typed domain and jumps to brands, pages, open alerts and recent
  scans; deep links (`#scan=`, `#hunt=`, `#intel=`, `#alert=`, `#page=`); an alert drawer with the
  full evidence, a character-level look-alike diff, a Unicode character inspector, related scans /
  certificates / sightings, notes, assignee, timeline, single-alert STIX and a printable HTML
  report; bulk triage of selected alerts; sortable tables; a brand filter and optional sound on
  the live feed; 24-hour sparklines on the dashboard and a certs/second sparkline on the feed;
  file import for the bulk scanner; a weekly HTML summary report; storage usage, retention purge
  and an installable PWA (manifest + service worker so the console opens offline).

### Changed
- `demo/index.html` was rebuilt around the new engine and application; the login/demo-account
  flow was replaced by an analyst landing page.
- README screenshots regenerated; `scripts/screenshots.py` follows the new landing flow and
  honours `CHROME_PATH` for a system Chromium.

## [2.1.0] - 2026-09-24

### Added
- **Domain parsing layer** (`src/utils/domain.py`): registrable-domain (eTLD+1) extraction
  with Kuwait (`com.kw`, `gov.kw`, ...), GCC/MENA and global second-level suffixes, free-hosting
  platforms treated as suffixes (`web.app`, `github.io`, `pages.dev` ...), punycode decoding,
  Unicode script detection, confusable-character skeletons, leetspeak folding and Arabic
  normalisation.
- **IDN homograph & mixed-script detection** (`nbк.com` → NBK) across the detector, analyzer
  and brand monitor.
- **Arabic language support**: Arabic brand keywords (الوطني, بيتك, كي نت ...) and Arabic lure
  words (تحديث, تفعيل, بطاقة ...) are detected inside IDN domains.
- **26 Kuwait brand profiles** (previously 10) including KNET, ABK, KIB, AUB, Al-Tijari, stc,
  PACI, MOH, MOE, Kuwait Airways, Jazeera Airways, KNPC, KPC, Boursa Kuwait and Talabat, with
  aliases, Arabic keywords and priorities. Custom profiles can be added via `brands:` in
  `config.yaml`.
- **Proactive typosquat watcher** (`main.py watch-squats`, `/api/v1/squats/*`): generates
  permutations of every protected brand across configurable TLDs, resolves them concurrently,
  persists sightings with first/last seen and triage status, and alerts when a new look-alike
  goes live.
- **Persisted alerts with a lifecycle**: `open → investigating → resolved / false_positive`,
  assignee, notes and a change history (`PATCH /api/v1/alerts/<id>`); resolving as a false
  positive can allowlist the domain in one call.
- **Allowlist** shared by every engine (`/api/v1/allowlist`, `main.py allowlist`).
- **Threat intelligence**: real OpenPhish feed matching (cached on disk), URLhaus host lookups,
  PhishTank, Google Safe Browsing v4, VirusTotal v3 and URLScan with an injectable fetcher,
  TTL cache, per-source error reporting and a synchronous wrapper.
- **Enrichment**: RDAP registration data (registrar, creation date, age, abuse contact),
  DNS and TLS certificate lookups (`/api/v1/enrich/<domain>`, `main.py scan --enrich`).
- **Notifications**: Microsoft Teams and Syslog/CEF channels, minimum-severity filtering,
  per-domain cooldown de-duplication and delivery statistics (`main.py test-notify`).
- **Exports & reporting**: STIX 2.1 bundles (`/api/v1/export/stix`, `main.py export-stix`),
  CSV/JSON alert exports, Markdown/JSON activity reports (`/api/v1/reports/summary`,
  `main.py report`) and a Prometheus `/metrics` endpoint.
- **API hardening**: HMAC-signed bearer tokens with expiry, optional static API key, roles
  (admin/analyst), sliding-window rate limiting with `X-RateLimit-*` headers, JSON error
  handlers, security headers, OpenAPI 3 document (`/api/v1/openapi.json`) and Swagger UI
  (`/api/v1/docs`).
- **CLI**: `bulk`, `permutations --resolve`, `watch-squats`, `report`, `allowlist`,
  `export-stix`, `config --check`, `test-notify`, `monitor --replay`, `scan --json/--intel/--enrich`,
  global `--config` and `--version`.
- **CertStream monitor**: per-certificate de-duplication of SANs and wildcards, token matching for
  short keywords (`kw`, `q8`), event persistence and a database heartbeat surfaced by
  `/api/v1/certstream/status`.
- **Configuration**: `config.local.yaml` / `KCW_CONFIG` resolution, every section (including
  `domain_analysis` and `database`, previously ignored) loaded with type coercion, many new
  `KCW_*` environment overrides, `validate()` warnings for insecure defaults.
- **Database**: schema versioning with automatic migration from 2.0.0 databases, scan history,
  allowlist, squat sightings, key/value state, alert history, daily time series, indicator export
  and retention purge.
- **Dashboard API mode**: when served by `main.py api` the dashboard detects the backend and uses
  it for sign-in (server credentials), scans with enrichment, alert triage buttons (investigate,
  resolve, false-positive + allowlist), a new **Typosquat Sightings** view with triage and
  on-demand brand checks, live statistics/charts, the stored CertStream feed and CSV/STIX export
  links. Demo mode (file:// or the demo button) is unchanged.
- `scripts/screenshots.py` now resolves paths relative to the repository and accepts a base URL.
- Test suite grew from 14 to 400+ offline tests; `pyproject.toml` / `.flake8` configure black
  (line length 100) and flake8; CI now lints `main.py` and runs a CLI smoke test.

### Changed
- Detection is performed on the registrable label instead of the first label, so
  `login.nbk.com.kw` and `nbk.com.verify-login.tk` are interpreted correctly.
- Typosquat thresholds scale with brand length: `nbk.com` is no longer reported as a typo of
  `kfh.com`, and single-bit "bitsquats" of three-letter brands (`nbc.com`, `abc.com`) require
  contextual signals.
- Brand alerts now carry a numeric risk score, a per-(brand, domain) de-duplication window and
  deterministic descriptions; the strongest match per brand wins and weaker matches against
  other brands are dropped as noise.
- Phishing scores were recalibrated: brand priority bonus, brand + lure keyword synergy, brand
  on risky TLD synergy, free-hosting platform indicator, fake `gov`/`ministry` wording and
  embedded `-com`/`-net` tokens.
- `PhishingVerdict`, `DomainAnalysisResult` and `BrandAlert` gained `to_dict()` and extra fields;
  API responses keep the 2.0.0 field names for compatibility.
- `Dockerfile` runs as a non-root user and its health check no longer depends on `curl`
  (which is absent from `python:slim`, so the old check never passed).
- `docker-compose.yml` adds the `kwtcyberwatch-watcher` service and secret-bearing env vars.

### Fixed
- `BrandMonitor` flagged every domain containing the letter `e` (from `e.gov.kw`) or `kw`.
- `DomainAnalyzer` reported protected brands as typosquats of each other.
- `load_config()` silently ignored the `domain_analysis` and `database` sections and never read
  `config.local.yaml` despite the README instructions.
- `main.py monitor` created a `DomainAnalyzer` it never used and alerted once per SAN.
- flake8 (unused imports) and black checks in CI were failing on `main`.

## [2.0.0] - 2026-03-08

### Added
- **Complete rewrite** with modular architecture
- **Interactive Web Dashboard** with real-time monitoring UI
  - Login authentication (demo: admin/admin)
  - Live CertStream feed visualization
  - Domain scanner with risk scoring
  - Brand protection alerts panel
  - Threat intelligence integration panel
  - Notification configuration panel
  - Geographic threat map
  - Analytics and statistics dashboard
- **Phishing Detection Engine** with multi-layered heuristic scoring
  - Keyword analysis (30+ phishing indicators)
  - Brand impersonation detection (Kuwait banks, telecom, government)
  - TLD risk assessment
  - Domain structure analysis
  - Shannon entropy calculation
  - IDN/Punycode attack detection
- **Domain Squatting Analyzer**
  - Typosquatting (Levenshtein distance)
  - Homoglyph attack detection (Unicode confusables)
  - Combo-squatting detection
  - Bitsquatting detection
  - Vowel swap detection
  - TLD swap detection
  - Subdomain abuse detection
  - Domain permutation generator
- **Brand Protection Monitor**
  - Pre-configured Kuwait brand profiles (NBK, KFH, CBK, Burgan, Gulf Bank, Boubyan, Warba, Zain, eGov, MOI)
  - Real-time brand alert generation
  - Alert lifecycle management
- **Notification System**
  - Email (SMTP) notifications with HTML templates
  - Slack webhook integration
  - Telegram Bot API integration
  - Generic webhook support with HMAC signing
  - Central dispatcher with severity routing
- **REST API** (Flask-based)
  - `/api/v1/scan/domain` — Single domain analysis
  - `/api/v1/scan/bulk` — Bulk domain scanning (up to 100)
  - `/api/v1/brands` — List monitored brands
  - `/api/v1/brands/permutations` — Generate squatting permutations
  - `/api/v1/alerts` — Retrieve and filter alerts
  - `/api/v1/stats` — Dashboard statistics
  - `/api/v1/certstream/status` — Monitor status
  - `/api/v1/health` — Health check
- **Threat Intelligence Integration** framework
  - VirusTotal API v3
  - URLScan.io
  - PhishTank
  - Google Safe Browsing
  - OpenPhish
- **Database** (SQLite) for persistent storage
- **Docker** support with docker-compose (API + Monitor services)
- **Configuration** via YAML with environment variable overrides
- **CLI** interface (`monitor`, `api`, `demo`, `scan <domain>`)
- **Community files**: CODEOWNERS, CODE_OF_CONDUCT, CONTRIBUTING, SUPPORT, SECURITY, issue/PR templates
- **CI/CD**: GitHub Actions for security scanning, linting, testing
- **Dependabot** configuration for automated dependency updates

### Changed
- Migrated from single-script to full modular Python package
- Enhanced keyword list with Kuwait-specific financial and government terms
- Improved CertStream reconnection with configurable exponential backoff

### Removed
- Legacy `code` and `code-sleep` scripts (preserved in v1.0.0 release)

## [1.0.0] - 2024-01-01

### Added
- Initial CertStream monitoring script
- Basic keyword filtering (kuwait, kw, kwt, kwi, q8)
- Domain logging to text file
- Exponential backoff retry logic

[2.2.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/SiteQ8/KWTCyberWatch/releases/tag/v1.0.0
