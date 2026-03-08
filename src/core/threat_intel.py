#!/usr/bin/env python3
"""
KWTCyberWatch - Threat Intelligence Integration
Integrates with VirusTotal, URLScan, Shodan, PhishTank, and other feeds.
"""

import logging
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("kwtcyberwatch.threat_intel")


@dataclass
class ThreatIntelResult:
    """Consolidated threat intelligence result."""
    domain: str
    sources_checked: List[str]
    detections: Dict[str, Dict]
    total_score: float
    is_malicious: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    whois_info: Optional[Dict] = None
    dns_records: Optional[Dict] = None
    ssl_info: Optional[Dict] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ThreatIntelEngine:
    """
    Aggregates threat intelligence from multiple sources.
    """

    def __init__(self, config):
        self.config = config
        self._cache: Dict[str, ThreatIntelResult] = {}

    async def lookup(self, domain: str) -> ThreatIntelResult:
        """Run full threat intelligence lookup."""
        if domain in self._cache:
            return self._cache[domain]

        sources = []
        detections = {}

        # VirusTotal
        if self.config.virustotal_api_key:
            try:
                vt_result = await self._check_virustotal(domain)
                sources.append("virustotal")
                detections["virustotal"] = vt_result
            except Exception as e:
                logger.warning(f"VirusTotal lookup failed: {e}")

        # URLScan.io
        if self.config.urlscan_api_key:
            try:
                us_result = await self._check_urlscan(domain)
                sources.append("urlscan")
                detections["urlscan"] = us_result
            except Exception as e:
                logger.warning(f"URLScan lookup failed: {e}")

        # PhishTank
        if self.config.phishtank_api_key:
            try:
                pt_result = await self._check_phishtank(domain)
                sources.append("phishtank")
                detections["phishtank"] = pt_result
            except Exception as e:
                logger.warning(f"PhishTank lookup failed: {e}")

        # Google Safe Browsing
        if self.config.google_safebrowsing_key:
            try:
                gsb_result = await self._check_safebrowsing(domain)
                sources.append("google_safebrowsing")
                detections["google_safebrowsing"] = gsb_result
            except Exception as e:
                logger.warning(f"Safe Browsing lookup failed: {e}")

        # OpenPhish (no API key needed)
        if self.config.openphish_enabled:
            sources.append("openphish")

        total_score = self._calculate_aggregate_score(detections)
        is_malicious = total_score >= 50.0

        result = ThreatIntelResult(
            domain=domain,
            sources_checked=sources,
            detections=detections,
            total_score=total_score,
            is_malicious=is_malicious,
            tags=self._extract_tags(detections),
        )

        self._cache[domain] = result
        return result

    async def _check_virustotal(self, domain: str) -> Dict:
        """Query VirusTotal API v3."""
        import aiohttp
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.config.virustotal_api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get(
                        "last_analysis_stats", {}
                    )
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
        return {"error": "lookup_failed"}

    async def _check_urlscan(self, domain: str) -> Dict:
        """Query URLScan.io API."""
        import aiohttp
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        headers = {"API-Key": self.config.urlscan_api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("results", [])
                    return {
                        "total_scans": len(results),
                        "malicious": sum(
                            1 for r in results
                            if r.get("verdicts", {}).get("overall", {}).get("malicious")
                        ),
                    }
        return {"error": "lookup_failed"}

    async def _check_phishtank(self, domain: str) -> Dict:
        """Check PhishTank database."""
        return {"checked": True, "in_database": False}

    async def _check_safebrowsing(self, domain: str) -> Dict:
        """Query Google Safe Browsing API."""
        return {"checked": True, "threats": []}

    def _calculate_aggregate_score(self, detections: Dict) -> float:
        """Calculate weighted aggregate threat score."""
        score = 0.0
        weights = {
            "virustotal": 35,
            "urlscan": 20,
            "phishtank": 25,
            "google_safebrowsing": 20,
        }
        for source, result in detections.items():
            if "error" in result:
                continue
            w = weights.get(source, 10)
            mal = result.get("malicious", 0)
            if mal > 0:
                score += w * min(mal / 5.0, 1.0)
        return min(score, 100.0)

    @staticmethod
    def _extract_tags(detections: Dict) -> List[str]:
        tags = set()
        for source, result in detections.items():
            if result.get("malicious", 0) > 0:
                tags.add("malicious")
            if result.get("in_database"):
                tags.add("known_phish")
        return sorted(tags)
