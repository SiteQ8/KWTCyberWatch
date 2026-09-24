# Changelog

All notable changes to KWTCyberWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-09-24

### Added
- **Relay feed**: `.github/workflows/ct-relay.yml` runs `scripts/ct_snapshot.py` (the project's own
  tailer) every 30 minutes for ~25 minutes and publishes Kuwait keyword matches to
  `demo/feed/latest.json` plus a 14-day archive. The console loads this same-origin feed next to
  direct tailing, so real matches arrive even where a browser cannot read a CT log directly.
- **Disclaimer and terms** (`DISCLAIMER.md`), surfaced on the website, the console landing page
  and sidebar, in generated reports and inside the published feed: findings are automated
  heuristics from public data, not accusations; brand names are used for identification only;
  no warranty; local-only data, no tracking.
- **Project website** at the GitHub Pages root (`index.html`, `404.html`, `.nojekyll`): features,
  how it works, screenshots, self-hosting quickstart and links to the live console.
- **Static CT API (tiled logs)** support in both tailers: `checkpoint` + `tile/data/...`
  (including partial `.p/W` tiles) with the `TileLeaf` format, tile-path encoding and
  discovery of `tiled_logs` from the log list. Newer logs from Let's Encrypt, Geomys and others
  are therefore covered alongside classic RFC 6962 logs; the feed table labels each kind.
- **Deep match**: the live feed now runs the brand engine on every certificate hostname, not
  only keyword hits, using a cheap skeleton prefilter (edit distance ≤ 1 or label containment)
  before the full monitor. Catches homoglyphs (`nbк.com`) and typos (`burgan-bnk.com`) that
  contain no keyword. Toggle under Settings → Engine & feed.
- **Custom detection rules**: regular expressions with a severity, managed under Settings,
  tested inline, applied to every feed hostname and every scan. Matches raise `custom_rule`
  alerts and add a scored indicator to scan results.
- **Alert consolidation**: a new alert for the same brand and registrable domain while one is
  already open increments an occurrence counter and records the extra hostnames (e.g. `www.`)
  instead of creating a duplicate; the alerts table shows `×N`.
- **Auto-enrichment**: new feed alerts are resolved over DoH and looked up via RDAP in the
  background; IPs, registrar and age land in the evidence and a `new` badge flags domains
  registered less than 30 days ago.

## [2.3.0] - 2026-09-24

### Added
- **Direct Certificate Transparency tailing — no third-party feed.** The public CertStream
  server (`certstream.calidog.io`) is no longer available, so the live feed was empty. Both the
  browser console (`demo/discovery.js`) and the backend (`src/core/ct_tailer.py`) now read the
  public CT logs themselves over RFC 6962 (`get-sth` / `get-entries`), discover current shards
  from Google's log list with a built-in fallback, skip logs that are offline or block
  cross-origin requests, and parse every DER certificate / pre-certificate with a small
  dependency-free X.509 reader (`src/utils/x509.py`, mirrored in JavaScript and parity-tested).
  The feed page shows each log's state, tree size, read rate and skipped entries, plus the
  session coverage. `main.py monitor` defaults to `--source ctlogs`; the CertStream WebSocket
  remains available as `--source certstream` / `certstream.source: certstream`.
- **Watchtower**: an automatic, scheduled brand sweep in the browser that generates look-alike
  domains for the protected brands (critical first, round-robin), resolves them over
  DNS-over-HTTPS (Google, Cloudflare fallback), records live ones as sightings and raises alerts.
  Toggle and "Sweep now" on the Sightings page; interval under Settings.
- **Expanded Kuwait keyword set** (84 keywords): `kuwait`, `kuwaiti`, `kw`, `kwt`, `kwi`, `q8`,
  `kuw`, Arabic `الكويت` / `الوطني` / `بيتك`, bank, payment (`knet`, `kpay`, `q8pay` …), telecom
  (`zain-kw`, `stckw` …), government (`moi-kw`, `paci-kw`, `sahel`, `civilid`, `egov-kw` …),
  aviation, energy and commerce identifiers. Existing browser workspaces merge the new defaults
  automatically; Arabic keywords match the Unicode form of IDN hostnames.
- DNS-over-HTTPS falls back to Cloudflare when Google's resolver is unreachable.

### Changed
- `demo/index.html`: the feed page is now "Certificate Transparency Live Feed" with a CT log
  table; Settings gain a feed source selector, extra CT log URLs and Watchtower controls.
- `certstream` (the Python package) is optional; it is only needed for the legacy WebSocket source.

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

[2.4.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/SiteQ8/KWTCyberWatch/releases/tag/v1.0.0
