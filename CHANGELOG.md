# Changelog

All notable changes to KWTCyberWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/SiteQ8/KWTCyberWatch/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/SiteQ8/KWTCyberWatch/releases/tag/v1.0.0
