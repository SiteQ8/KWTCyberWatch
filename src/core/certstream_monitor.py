#!/usr/bin/env python3
"""
KWTCyberWatch - CertStream Monitor
Real-time Certificate Transparency log monitoring for suspicious domain detection.
"""

import re
import json
import logging
import time
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, asdict

try:
    import certstream
except ImportError:
    certstream = None

logger = logging.getLogger("kwtcyberwatch.certstream")


@dataclass
class CertificateEvent:
    """Represents a parsed certificate transparency event."""
    domain: str
    all_domains: List[str]
    issuer: str
    fingerprint: str
    not_before: str
    not_after: str
    serial_number: str
    source: str
    timestamp: str
    matched_keywords: List[str]
    risk_score: float = 0.0
    is_wildcard: bool = False


class CertStreamMonitor:
    """
    Monitors Certificate Transparency logs via CertStream for suspicious
    domains matching configurable keyword patterns.
    """

    def __init__(self, config):
        self.config = config
        self.keywords = config.keywords
        self.url = config.url
        self.retry_delay = config.retry_delay
        self.max_delay = config.max_delay
        self.callbacks: List[Callable] = []
        self.stats = {
            "total_certs": 0,
            "matched_certs": 0,
            "start_time": None,
            "last_event": None,
        }
        self._running = False

    def add_callback(self, callback: Callable):
        """Register a callback for matched certificate events."""
        self.callbacks.append(callback)

    def _calculate_risk_score(self, domain: str, cert_data: dict) -> float:
        """Calculate risk score based on multiple heuristics."""
        score = 0.0

        # Keyword density
        keyword_hits = sum(1 for kw in self.keywords if kw.lower() in domain.lower())
        score += min(keyword_hits * 15, 40)

        # Suspicious TLD patterns
        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site", ".icu",
                          ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 20

        # Entropy check (high entropy = random = suspicious)
        entropy = self._calculate_entropy(domain.split(".")[0])
        if entropy > 3.5:
            score += 15

        # Length-based heuristic
        base_domain = domain.split(".")[0]
        if len(base_domain) > 20:
            score += 10

        # Hyphen abuse
        if base_domain.count("-") >= 3:
            score += 15

        # Number padding
        if re.search(r"\d{4,}", base_domain):
            score += 10

        # Let's Encrypt (common for phishing)
        issuer = cert_data.get("issuer", {})
        if "Let's Encrypt" in str(issuer):
            score += 5

        # Subdomain depth
        if domain.count(".") >= 4:
            score += 10

        return min(score, 100.0)

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        import math
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length)
                     for count in freq.values())

    def _handle_message(self, message, context):
        """Process incoming CertStream messages."""
        if message.get("message_type") != "certificate_update":
            return

        self.stats["total_certs"] += 1

        try:
            leaf = message["data"]["leaf_cert"]
            all_domains = leaf.get("all_domains", [])
            issuer = leaf.get("issuer", {})
            fingerprint = leaf.get("fingerprint", "")
            not_before = leaf.get("not_before", "")
            not_after = leaf.get("not_after", "")
            serial = leaf.get("serial_number", "")
            source = message["data"].get("source", {}).get("name", "unknown")

            for domain in all_domains:
                matched_keywords = [
                    kw for kw in self.keywords
                    if kw.lower() in domain.lower()
                ]

                if matched_keywords:
                    risk_score = self._calculate_risk_score(domain, message["data"])

                    event = CertificateEvent(
                        domain=domain,
                        all_domains=all_domains,
                        issuer=json.dumps(issuer),
                        fingerprint=fingerprint,
                        not_before=not_before,
                        not_after=not_after,
                        serial_number=serial,
                        source=source,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        matched_keywords=matched_keywords,
                        risk_score=risk_score,
                        is_wildcard=domain.startswith("*."),
                    )

                    self.stats["matched_certs"] += 1
                    self.stats["last_event"] = event.timestamp

                    logger.info(
                        f"[MATCH] {domain} | Risk: {risk_score:.0f} | "
                        f"Keywords: {matched_keywords}"
                    )

                    for callback in self.callbacks:
                        try:
                            callback(event)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")

        except (KeyError, TypeError) as e:
            logger.debug(f"Parse error: {e}")

    def start(self):
        """Start monitoring CertStream with exponential backoff retry."""
        if certstream is None:
            raise ImportError("certstream package not installed: pip install certstream")

        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        retry_delay = self.retry_delay

        logger.info(f"Starting CertStream monitor | Keywords: {len(self.keywords)}")

        while self._running:
            try:
                certstream.listen_for_events(
                    self._handle_message, url=self.url
                )
            except Exception as e:
                logger.warning(f"CertStream error: {e}. Retry in {retry_delay}s")
                time.sleep(retry_delay)
                retry_delay = min(self.max_delay, retry_delay * 2)

    def stop(self):
        """Stop the monitor."""
        self._running = False
        logger.info("CertStream monitor stopped")

    def get_stats(self) -> dict:
        """Return monitoring statistics."""
        return dict(self.stats)
