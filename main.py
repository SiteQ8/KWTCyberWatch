#!/usr/bin/env python3
"""
KWTCyberWatch - Kuwait Phishing Detection & Brand Protection Suite
Main entry point for running all components.

Usage:
    python main.py monitor     - Start CertStream monitoring
    python main.py api         - Start API server
    python main.py scan <domain> - Scan a single domain
    python main.py demo        - Start API server with demo dashboard
"""

import sys
import logging
import argparse
from datetime import datetime, timezone

from src.config.settings import load_config
from src.core.certstream_monitor import CertStreamMonitor
from src.core.phishing_detector import PhishingDetector
from src.core.domain_analyzer import DomainAnalyzer
from src.core.brand_monitor import BrandMonitor
from src.notifications.dispatcher import NotificationDispatcher, Alert
from src.models.database import Database


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("kwtcyberwatch")

BANNER = r"""
 _  ____        _______ ____      _               __        __    _       _     
| |/ /\ \      / /_   _/ ___|   _| |__   ___ _ __ \ \      / /_ _| |_ ___| |__  
| ' /  \ \ /\ / /  | || |  | | | | '_ \ / _ \ '__| \ \ /\ / / _` | __/ __| '_ \ 
| . \   \ V  V /   | || |__| |_| | |_) |  __/ |     \ V  V / (_| | || (__| | | |
|_|\_\   \_/\_/    |_| \____\__, |_.__/ \___|_|      \_/\_/ \__,_|\__\___|_| |_|
                             |___/                                        v2.0.0
    Kuwait Phishing Detection & Brand Protection Suite
    By Ali AlEnezi (@SiteQ8) | Site@hotmail.com
"""


def cmd_monitor(config):
    """Start CertStream real-time monitoring."""
    db = Database(config.database.db_path)
    detector = PhishingDetector(config)
    analyzer = DomainAnalyzer(config.domain_analysis)
    brand_mon = BrandMonitor()
    notifier = NotificationDispatcher(config.notifications)

    def on_cert_event(event):
        verdict = detector.analyze(event.domain)
        db.add_domain(
            domain=event.domain,
            risk_score=verdict.risk_score,
            risk_level=verdict.risk_level,
            is_phishing=verdict.is_phishing,
            categories=verdict.categories,
            source="certstream",
            keywords=event.matched_keywords,
        )

        brand_alerts = brand_mon.check_domain(event.domain)
        for ba in brand_alerts:
            if ba.severity in ("critical", "high"):
                notifier.dispatch(Alert(
                    title=f"Brand Alert: {ba.brand_name}",
                    message=ba.description,
                    severity=ba.severity,
                    domain=event.domain,
                    alert_type=ba.alert_type,
                    details=ba.evidence,
                ))

        if verdict.risk_level in ("critical", "high"):
            logger.warning(
                f"🚨 HIGH RISK: {event.domain} | Score: {verdict.risk_score:.0f} | "
                f"Level: {verdict.risk_level}"
            )

    monitor = CertStreamMonitor(config.certstream)
    monitor.add_callback(on_cert_event)

    logger.info("Starting CertStream monitor...")
    monitor.start()


def cmd_scan(config, domain: str):
    """Scan a single domain."""
    detector = PhishingDetector(config)
    analyzer = DomainAnalyzer(config.domain_analysis)
    brand_mon = BrandMonitor()

    print(f"\n{'='*60}")
    print(f"  Scanning: {domain}")
    print(f"{'='*60}\n")

    verdict = detector.analyze(domain)
    print(f"  Phishing Detection:")
    print(f"    Risk Score:  {verdict.risk_score:.1f}/100")
    print(f"    Risk Level:  {verdict.risk_level.upper()}")
    print(f"    Is Phishing: {'YES' if verdict.is_phishing else 'No'}")
    print(f"    Categories:  {', '.join(verdict.categories) or 'None'}")
    print(f"    Confidence:  {verdict.confidence:.1%}")
    print()

    if verdict.indicators:
        print(f"  Indicators ({len(verdict.indicators)}):")
        for ind in verdict.indicators:
            print(f"    • {ind['type']}: {ind['detail']} (weight: {ind['weight']})")
        print()

    squat_results = analyzer.analyze(domain)
    if squat_results:
        print(f"  Domain Squatting Analysis:")
        for r in squat_results:
            print(f"    Target:   {r.target_domain}")
            print(f"    Attacks:  {', '.join(r.attack_types)}")
            print(f"    Similarity: {r.similarity_score:.1%}")
            print(f"    Risk:     {r.risk_level.upper()}")
            print()

    brand_alerts = brand_mon.check_domain(domain)
    if brand_alerts:
        print(f"  Brand Alerts ({len(brand_alerts)}):")
        for a in brand_alerts:
            print(f"    [{a.severity.upper()}] {a.brand_name}: {a.description}")
        print()

    print(f"  Recommendation: {verdict.recommendation}")
    print(f"\n{'='*60}\n")


def cmd_api(config):
    """Start the API server."""
    from src.api.app import app
    logger.info(f"Starting API server on {config.api.host}:{config.api.port}")
    app.run(
        host=config.api.host,
        port=config.api.port,
        debug=config.api.debug,
    )


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="KWTCyberWatch - Phishing Detection Suite")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("monitor", help="Start CertStream monitoring")
    subparsers.add_parser("api", help="Start API server")
    subparsers.add_parser("demo", help="Start API with demo dashboard")

    scan_parser = subparsers.add_parser("scan", help="Scan a domain")
    scan_parser.add_argument("domain", help="Domain to scan")

    args = parser.parse_args()
    config = load_config()

    if args.command == "monitor":
        cmd_monitor(config)
    elif args.command == "scan":
        cmd_scan(config, args.domain)
    elif args.command in ("api", "demo"):
        config.api.debug = True
        cmd_api(config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
