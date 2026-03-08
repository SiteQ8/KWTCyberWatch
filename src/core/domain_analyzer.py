#!/usr/bin/env python3
"""
KWTCyberWatch - Domain Squatting Analyzer
Detects typosquatting, homoglyph attacks, combo-squatting, and other
domain impersonation techniques.
"""

import re
import math
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("kwtcyberwatch.domain_analyzer")

# Unicode homoglyph mapping for IDN attacks
HOMOGLYPHS = {
    "a": ["à", "á", "â", "ã", "ä", "å", "ɑ", "а", "ạ"],
    "b": ["d", "ḅ", "ʙ", "Ь"],
    "c": ["ç", "ć", "с", "ϲ"],
    "d": ["b", "ḍ", "ɗ"],
    "e": ["è", "é", "ê", "ë", "ē", "е", "ẹ"],
    "g": ["q", "ɡ", "ɢ"],
    "h": ["ḥ", "ħ", "н"],
    "i": ["1", "l", "í", "ì", "î", "ï", "і"],
    "k": ["ḳ", "ĸ", "к"],
    "l": ["1", "i", "ł", "ℓ"],
    "m": ["rn", "ṃ", "м"],
    "n": ["ñ", "ṇ", "п"],
    "o": ["0", "ó", "ò", "ô", "õ", "ö", "ø", "о", "ọ"],
    "p": ["ṗ", "р"],
    "q": ["g", "ɋ"],
    "r": ["ṛ", "ŗ", "г"],
    "s": ["5", "$", "ṣ", "ś", "ş", "ѕ"],
    "t": ["ṭ", "ţ", "т"],
    "u": ["ú", "ù", "û", "ü", "ū", "µ", "ц"],
    "v": ["ṿ", "ν", "ѵ"],
    "w": ["ẁ", "ẃ", "ш", "ω"],
    "x": ["ẋ", "х"],
    "y": ["ý", "ÿ", "ŷ", "у"],
    "z": ["ẓ", "ź", "ż", "з"],
}

# Common typosquatting keyboard adjacency map (QWERTY)
KEYBOARD_ADJACENT = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yijh", "i": "uojk", "o": "iplk", "p": "ol",
    "a": "qwsz", "s": "weadxz", "d": "ersfxc", "f": "rtdgcv",
    "g": "tyfhvb", "h": "yugjbn", "j": "uihknm", "k": "oijlm",
    "l": "pk", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}


@dataclass
class DomainAnalysisResult:
    """Result of domain squatting analysis."""
    target_domain: str
    suspicious_domain: str
    attack_types: List[str]
    similarity_score: float
    risk_level: str  # critical, high, medium, low
    details: Dict
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    whois_data: Optional[Dict] = None
    dns_records: Optional[Dict] = None


class DomainAnalyzer:
    """
    Analyzes domains for various squatting and impersonation techniques.
    """

    def __init__(self, config):
        self.config = config
        self.protected_brands = config.protected_brands

    def analyze(self, domain: str) -> List[DomainAnalysisResult]:
        """Run full analysis against all protected brands."""
        results = []
        domain_lower = domain.lower().strip()

        for brand in self.protected_brands:
            brand_lower = brand.lower().strip()
            brand_base = brand_lower.split(".")[0]
            domain_base = domain_lower.split(".")[0]

            if domain_lower == brand_lower:
                continue

            attacks = []
            details = {}

            # 1. Levenshtein distance (typosquatting)
            lev_dist = self._levenshtein(domain_base, brand_base)
            if 0 < lev_dist <= self.config.levenshtein_threshold:
                attacks.append("typosquatting")
                details["levenshtein_distance"] = lev_dist

            # 2. Homoglyph detection
            if self._check_homoglyph(domain_base, brand_base):
                attacks.append("homoglyph")
                details["homoglyph_detected"] = True

            # 3. Combo-squatting (brand + keyword)
            combo_keywords = [
                "login", "signin", "secure", "verify", "update", "account",
                "support", "service", "online", "portal", "auth", "bank",
                "pay", "wallet", "mobile", "app", "web", "mail", "cloud",
                "admin", "reset", "confirm", "validation"
            ]
            if brand_base in domain_base and domain_base != brand_base:
                for kw in combo_keywords:
                    if kw in domain_base:
                        attacks.append("combo-squatting")
                        details["combo_keyword"] = kw
                        break
                if "combo-squatting" not in attacks:
                    attacks.append("brand-impersonation")

            # 4. Subdomain abuse
            if brand_base in domain_lower and domain_lower.count(".") >= 3:
                attacks.append("subdomain-abuse")
                details["subdomain_depth"] = domain_lower.count(".")

            # 5. TLD swap
            if domain_base == brand_base:
                domain_tld = ".".join(domain_lower.split(".")[1:])
                brand_tld = ".".join(brand_lower.split(".")[1:])
                if domain_tld != brand_tld:
                    attacks.append("tld-swap")
                    details["original_tld"] = brand_tld
                    details["swapped_tld"] = domain_tld

            # 6. Bitsquatting
            if self._check_bitsquat(domain_base, brand_base):
                attacks.append("bitsquatting")

            # 7. Vowel swap
            if self._check_vowel_swap(domain_base, brand_base):
                attacks.append("vowel-swap")

            # 8. Hyphenation
            if domain_base.replace("-", "") == brand_base:
                attacks.append("hyphenation")

            if attacks:
                similarity = self._similarity_score(domain_base, brand_base)
                risk = self._calculate_risk_level(attacks, similarity)

                results.append(DomainAnalysisResult(
                    target_domain=brand,
                    suspicious_domain=domain,
                    attack_types=attacks,
                    similarity_score=similarity,
                    risk_level=risk,
                    details=details,
                ))

        return results

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance."""
        if len(s1) < len(s2):
            return DomainAnalyzer._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def _check_homoglyph(domain: str, brand: str) -> bool:
        """Check if domain uses homoglyph characters to impersonate brand."""
        if len(domain) != len(brand):
            return False
        diff_count = 0
        for d, b in zip(domain, brand):
            if d != b:
                if b in HOMOGLYPHS and d in HOMOGLYPHS.get(b, []):
                    diff_count += 1
                else:
                    return False
        return diff_count > 0

    @staticmethod
    def _check_bitsquat(domain: str, brand: str) -> bool:
        """Check for single-bit flip differences (bitsquatting)."""
        if len(domain) != len(brand):
            return False
        flip_count = 0
        for d, b in zip(domain, brand):
            xor = ord(d) ^ ord(b)
            if xor != 0:
                if bin(xor).count("1") == 1:
                    flip_count += 1
                else:
                    return False
        return flip_count == 1

    @staticmethod
    def _check_vowel_swap(domain: str, brand: str) -> bool:
        """Check for vowel substitution attacks."""
        vowels = set("aeiou")
        if len(domain) != len(brand):
            return False
        swap_count = 0
        for d, b in zip(domain, brand):
            if d != b:
                if d in vowels and b in vowels:
                    swap_count += 1
                else:
                    return False
        return swap_count > 0

    @staticmethod
    def _similarity_score(s1: str, s2: str) -> float:
        """Calculate normalized similarity score (0-1)."""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        dist = DomainAnalyzer._levenshtein(s1, s2)
        return 1.0 - (dist / max_len)

    @staticmethod
    def _calculate_risk_level(attacks: List[str], similarity: float) -> str:
        """Determine risk level from attack types and similarity."""
        high_risk_attacks = {"homoglyph", "bitsquatting", "combo-squatting"}
        if any(a in high_risk_attacks for a in attacks) and similarity > 0.8:
            return "critical"
        if similarity > 0.85 or len(attacks) >= 2:
            return "high"
        if similarity > 0.7:
            return "medium"
        return "low"

    def generate_permutations(self, brand: str) -> List[str]:
        """Generate all possible squatting permutations of a brand domain."""
        base = brand.split(".")[0]
        permutations = set()

        # Typosquatting: character omission
        for i in range(len(base)):
            permutations.add(base[:i] + base[i + 1:])

        # Typosquatting: character swap
        for i in range(len(base) - 1):
            perm = list(base)
            perm[i], perm[i + 1] = perm[i + 1], perm[i]
            permutations.add("".join(perm))

        # Typosquatting: keyboard adjacent
        for i, c in enumerate(base):
            if c in KEYBOARD_ADJACENT:
                for adj in KEYBOARD_ADJACENT[c]:
                    permutations.add(base[:i] + adj + base[i + 1:])

        # Character doubling
        for i in range(len(base)):
            permutations.add(base[:i] + base[i] + base[i:])

        # Hyphenation
        for i in range(1, len(base)):
            permutations.add(base[:i] + "-" + base[i:])

        # Homoglyph
        for i, c in enumerate(base):
            if c in HOMOGLYPHS:
                for h in HOMOGLYPHS[c][:3]:
                    permutations.add(base[:i] + h + base[i + 1:])

        return sorted(permutations)
