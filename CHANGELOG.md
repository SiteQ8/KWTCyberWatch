# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-08

### Added
- Modern web dashboard with dark theme UI
- Login page with authentication (demo credentials: `admin` / `CyberWatch2024!`)
- Real-time alert dashboard with threat categorization
- Alert center with filtering by risk level and status
- Monitoring status page with connection health indicators
- Settings page with toggle controls for notifications and monitoring
- Activity feed with live threat updates
- Keyword tracking panel showing monitored terms
- Stats cards showing certificates monitored, alerts, and blocked domains
- Flask-based web application (`webapp/`)
- Properly structured Python monitoring scripts (`scripts/`)
- Comprehensive project documentation (README, CONTRIBUTING, SUPPORT, SECURITY)
- GitHub community files (CODE_OF_CONDUCT, CODEOWNERS, issue/PR templates)
- GitHub Actions security scanning workflow
- Dependabot configuration for automated dependency updates
- `.gitignore` for Python/Flask projects
- `requirements.txt` with project dependencies

### Changed
- Reorganized monitoring scripts from root to `scripts/` directory
- Renamed `code` to `certstream_monitor.py` with proper documentation
- Renamed `code-sleep` to `certstream_monitor_resilient.py` with proper documentation
- Updated LICENSE to MIT

## [1.0.0] - 2024-11-07

### Added
- Initial CertStream monitoring script (`code`)
- Enhanced monitoring script with exponential backoff retry (`code-sleep`)
- Kuwait-related domain keyword filtering (kuwait, kw, kwt, kwi, q8)
- Domain logging to `filtered_domains.txt`
