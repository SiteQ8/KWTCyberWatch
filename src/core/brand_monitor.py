#!/usr/bin/env python3
"""
KWTCyberWatch - Brand Protection Monitor
Monitors and protects brand assets against phishing and impersonation.
"""

import logging
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("kwtcyberwatch.brand_monitor")


@dataclass
class BrandProfile:
    """Defines a brand to protect."""
    name: str
    domains: List[str]
    keywords: List[str]
    logos: List[str] = field(default_factory=list)
    social_handles: Dict[str, str] = field(default_factory=dict)
    industry: str = ""
    priority: str = "high"  # critical, high, medium, low


@dataclass
class BrandAlert:
    """Alert generated when brand impersonation is detected."""
    alert_id: str
    brand_name: str
    alert_type: str  # domain_squat, cert_abuse, social_impersonation, content_clone
    severity: str
    description: str
    evidence: Dict
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: str = "open"  # open, investigating, resolved, false_positive
    assignee: Optional[str] = None


# Default Kuwait brand profiles for monitoring
KUWAIT_BRANDS = [
    BrandProfile(
        name="National Bank of Kuwait (NBK)",
        domains=["nbk.com", "nbk.com.kw"],
        keywords=["nbk", "national bank kuwait"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Kuwait Finance House (KFH)",
        domains=["kfh.com", "kfh.com.kw"],
        keywords=["kfh", "kuwait finance"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Central Bank of Kuwait (CBK)",
        domains=["cbk.gov.kw"],
        keywords=["cbk", "central bank kuwait"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Burgan Bank",
        domains=["burgan.com", "burgan.com.kw"],
        keywords=["burgan", "burgan bank"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Gulf Bank",
        domains=["e-gulfbank.com", "gulfbank.com.kw"],
        keywords=["gulfbank", "gulf bank kuwait"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Boubyan Bank",
        domains=["bankboubyan.com"],
        keywords=["boubyan", "boubyan bank"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Warba Bank",
        domains=["warbabank.com"],
        keywords=["warba", "warba bank"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Zain Kuwait",
        domains=["kw.zain.com", "zain.com"],
        keywords=["zain kuwait", "zain kw"],
        industry="telecom",
        priority="high",
    ),
    BrandProfile(
        name="Kuwait eGovernment",
        domains=["e.gov.kw"],
        keywords=["egov kuwait", "e.gov.kw"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Ministry of Interior Kuwait",
        domains=["moi.gov.kw"],
        keywords=["moi kuwait", "kuwait moi"],
        industry="government",
        priority="critical",
    ),
]


class BrandMonitor:
    """
    Monitors brand assets and generates alerts on impersonation attempts.
    """

    def __init__(self, brands: Optional[List[BrandProfile]] = None):
        self.brands = brands or KUWAIT_BRANDS
        self.alerts: List[BrandAlert] = []
        self._alert_counter = 0

    def add_brand(self, brand: BrandProfile):
        """Add a brand to monitor."""
        self.brands.append(brand)
        logger.info(f"Added brand monitor: {brand.name}")

    def check_domain(self, domain: str) -> List[BrandAlert]:
        """Check a domain against all monitored brands."""
        alerts = []
        domain_lower = domain.lower()

        for brand in self.brands:
            for protected in brand.domains:
                base = protected.split(".")[0].lower()

                # Direct keyword match in domain
                if base in domain_lower and domain_lower != protected.lower():
                    self._alert_counter += 1
                    alert = BrandAlert(
                        alert_id=f"BA-{self._alert_counter:06d}",
                        brand_name=brand.name,
                        alert_type="domain_squat",
                        severity=brand.priority,
                        description=(
                            f"Potential domain squatting detected for {brand.name}: "
                            f"{domain} (protected: {protected})"
                        ),
                        evidence={
                            "suspicious_domain": domain,
                            "protected_domain": protected,
                            "brand": brand.name,
                        },
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)

            # Keyword-based detection
            for keyword in brand.keywords:
                if keyword.lower() in domain_lower:
                    is_legit = any(
                        domain_lower.endswith(d.lower()) for d in brand.domains
                    )
                    if not is_legit:
                        self._alert_counter += 1
                        alert = BrandAlert(
                            alert_id=f"BA-{self._alert_counter:06d}",
                            brand_name=brand.name,
                            alert_type="brand_keyword_abuse",
                            severity="medium",
                            description=(
                                f"Brand keyword '{keyword}' found in domain: {domain}"
                            ),
                            evidence={
                                "suspicious_domain": domain,
                                "matched_keyword": keyword,
                                "brand": brand.name,
                            },
                        )
                        alerts.append(alert)
                        self.alerts.append(alert)

        return alerts

    def get_alerts(self, status: Optional[str] = None,
                   severity: Optional[str] = None) -> List[BrandAlert]:
        """Retrieve filtered alerts."""
        results = self.alerts
        if status:
            results = [a for a in results if a.status == status]
        if severity:
            results = [a for a in results if a.severity == severity]
        return results

    def get_stats(self) -> Dict:
        """Return brand monitoring statistics."""
        return {
            "total_brands": len(self.brands),
            "total_alerts": len(self.alerts),
            "open_alerts": len([a for a in self.alerts if a.status == "open"]),
            "critical_alerts": len([a for a in self.alerts if a.severity == "critical"]),
            "by_type": self._count_by("alert_type"),
            "by_severity": self._count_by("severity"),
            "by_brand": self._count_by("brand_name"),
        }

    def _count_by(self, field: str) -> Dict[str, int]:
        counts = {}
        for alert in self.alerts:
            val = getattr(alert, field)
            counts[val] = counts.get(val, 0) + 1
        return counts
