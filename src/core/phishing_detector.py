#!/usr/bin/env python3
"""
KWTCyberWatch - Phishing Detection Engine
Multi-layered heuristic and ML-based phishing detection.
"""

import re
import math
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("kwtcyberwatch.phishing_detector")


@dataclass
class PhishingVerdict:
    """Result of phishing analysis."""
    domain: str
    is_phishing: bool
    confidence: float
    risk_score: float
    risk_level: str  # critical, high, medium, low, clean
    indicators: List[Dict]
    categories: List[str]
    recommendation: str
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# Phishing indicator patterns
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "verify", "verification",
    "secure", "security", "update", "confirm", "account", "suspend",
    "restrict", "unlock", "recover", "validate", "authenticate",
    "banking", "payment", "wallet", "credential", "password",
    "ssn", "social-security", "tax-refund", "irs",
]

BRAND_IMPERSONATION_KEYWORDS = [
    "microsoft", "apple", "google", "amazon", "paypal", "netflix",
    "facebook", "instagram", "whatsapp", "telegram", "linkedin",
    "outlook", "office365", "onedrive", "dropbox", "adobe",
    "nbk", "kfh", "cbk", "burgan", "gulfbank", "boubyan", "warba",
    "zain", "ooredoo", "stc", "kuwait-airways",
]

SUSPICIOUS_TLDS = {
    "high_risk": [".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".icu"],
    "medium_risk": [".xyz", ".top", ".club", ".online", ".site", ".work",
                    ".click", ".link", ".info", ".biz", ".pw"],
}


class PhishingDetector:
    """Multi-layered phishing detection engine."""

    def __init__(self, config=None):
        self.config = config
        self.detection_count = 0
        self.false_positive_domains: set = set()

    def analyze(self, domain: str, additional_context: Optional[Dict] = None) -> PhishingVerdict:
        """Run comprehensive phishing analysis on a domain."""
        indicators = []
        categories = set()
        total_score = 0.0

        domain_lower = domain.lower().strip()
        parts = domain_lower.split(".")
        base_domain = parts[0] if parts else domain_lower

        # 1. Keyword analysis
        score, kw_indicators = self._check_keywords(domain_lower, base_domain)
        total_score += score
        indicators.extend(kw_indicators)
        if kw_indicators:
            categories.add("keyword_abuse")

        # 2. Brand impersonation
        score, brand_indicators = self._check_brand_impersonation(domain_lower)
        total_score += score
        indicators.extend(brand_indicators)
        if brand_indicators:
            categories.add("brand_impersonation")

        # 3. TLD risk
        score, tld_indicators = self._check_tld_risk(domain_lower)
        total_score += score
        indicators.extend(tld_indicators)
        if tld_indicators:
            categories.add("suspicious_tld")

        # 4. Domain structure analysis
        score, struct_indicators = self._analyze_structure(domain_lower, base_domain)
        total_score += score
        indicators.extend(struct_indicators)
        if struct_indicators:
            categories.add("structural_anomaly")

        # 5. Entropy analysis
        score, entropy_indicators = self._check_entropy(base_domain)
        total_score += score
        indicators.extend(entropy_indicators)
        if entropy_indicators:
            categories.add("high_entropy")

        # 6. Punycode / IDN detection
        score, idn_indicators = self._check_idn(domain_lower)
        total_score += score
        indicators.extend(idn_indicators)
        if idn_indicators:
            categories.add("idn_attack")

        # Normalize score
        risk_score = min(total_score, 100.0)
        risk_level = self._score_to_level(risk_score)
        is_phishing = risk_score >= 50.0

        if domain_lower in self.false_positive_domains:
            is_phishing = False
            risk_level = "clean"
            risk_score = 0.0

        recommendation = self._generate_recommendation(risk_level, categories)

        self.detection_count += 1

        return PhishingVerdict(
            domain=domain,
            is_phishing=is_phishing,
            confidence=min(risk_score / 100.0, 0.99),
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            categories=sorted(categories),
            recommendation=recommendation,
        )

    def _check_keywords(self, domain: str, base: str) -> Tuple[float, List[Dict]]:
        indicators = []
        score = 0.0
        for kw in PHISHING_KEYWORDS:
            if kw in domain:
                weight = 12.0 if kw in base else 6.0
                score += weight
                indicators.append({
                    "type": "phishing_keyword",
                    "detail": f"Phishing keyword '{kw}' found",
                    "weight": weight,
                })
        return min(score, 35.0), indicators

    def _check_brand_impersonation(self, domain: str) -> Tuple[float, List[Dict]]:
        indicators = []
        score = 0.0
        for brand in BRAND_IMPERSONATION_KEYWORDS:
            if brand in domain:
                score += 20.0
                indicators.append({
                    "type": "brand_impersonation",
                    "detail": f"Brand keyword '{brand}' detected in domain",
                    "weight": 20.0,
                })
                break
        return min(score, 25.0), indicators

    def _check_tld_risk(self, domain: str) -> Tuple[float, List[Dict]]:
        indicators = []
        score = 0.0
        for tld in SUSPICIOUS_TLDS["high_risk"]:
            if domain.endswith(tld):
                score += 20.0
                indicators.append({
                    "type": "high_risk_tld",
                    "detail": f"High-risk TLD: {tld}",
                    "weight": 20.0,
                })
        for tld in SUSPICIOUS_TLDS["medium_risk"]:
            if domain.endswith(tld):
                score += 10.0
                indicators.append({
                    "type": "medium_risk_tld",
                    "detail": f"Medium-risk TLD: {tld}",
                    "weight": 10.0,
                })
        return score, indicators

    def _analyze_structure(self, domain: str, base: str) -> Tuple[float, List[Dict]]:
        indicators = []
        score = 0.0

        # Excessive subdomains
        dot_count = domain.count(".")
        if dot_count >= 4:
            score += 15.0
            indicators.append({
                "type": "excessive_subdomains",
                "detail": f"Domain has {dot_count} levels",
                "weight": 15.0,
            })

        # Excessive hyphens
        hyphen_count = base.count("-")
        if hyphen_count >= 3:
            score += 12.0
            indicators.append({
                "type": "excessive_hyphens",
                "detail": f"Base domain contains {hyphen_count} hyphens",
                "weight": 12.0,
            })

        # Very long domain
        if len(base) > 25:
            score += 8.0
            indicators.append({
                "type": "long_domain",
                "detail": f"Unusually long base domain ({len(base)} chars)",
                "weight": 8.0,
            })

        # Numeric padding
        if re.search(r"\d{5,}", base):
            score += 10.0
            indicators.append({
                "type": "numeric_padding",
                "detail": "Contains long numeric sequence",
                "weight": 10.0,
            })

        return score, indicators

    def _check_entropy(self, base: str) -> Tuple[float, List[Dict]]:
        indicators = []
        score = 0.0
        if not base:
            return 0.0, []
        freq = {}
        for c in base:
            freq[c] = freq.get(c, 0) + 1
        length = len(base)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        if entropy > 4.0:
            score += 12.0
            indicators.append({
                "type": "high_entropy",
                "detail": f"High entropy score: {entropy:.2f}",
                "weight": 12.0,
            })
        return score, indicators

    def _check_idn(self, domain: str) -> Tuple[float, List[Dict]]:
        indicators = []
        score = 0.0
        if domain.startswith("xn--") or any(
            part.startswith("xn--") for part in domain.split(".")
        ):
            score += 18.0
            indicators.append({
                "type": "punycode_idn",
                "detail": "Internationalized Domain Name (punycode) detected",
                "weight": 18.0,
            })
        return score, indicators

    @staticmethod
    def _score_to_level(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "clean"

    @staticmethod
    def _generate_recommendation(level: str, categories: set) -> str:
        recs = {
            "critical": "IMMEDIATE ACTION: Block domain, issue takedown request, notify SOC team.",
            "high": "HIGH PRIORITY: Add to blocklist, investigate registration details, monitor for active phishing.",
            "medium": "MONITOR: Add to watchlist, verify with threat intelligence feeds.",
            "low": "LOW RISK: Log for reference, no immediate action required.",
            "clean": "No threats detected. Domain appears legitimate.",
        }
        return recs.get(level, "Review manually.")
