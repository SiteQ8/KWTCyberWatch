#!/usr/bin/env python3
"""
Parity tests between the Python engine and its browser port (demo/engine.js).

Requires Node.js; the comparison tests are skipped when ``node`` is missing.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.config.settings import DomainAnalysisConfig
from src.core.brand_monitor import BrandMonitor
from src.core.domain_analyzer import DomainAnalyzer
from src.core.phishing_detector import PhishingDetector

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

CORPUS = [
    # legitimate
    "nbk.com",
    "login.nbk.com",
    "www.nbk.com.kw",
    "kfh.com",
    "e.gov.kw",
    "kw.zain.com",
    "google.com",
    "paypal.com",
    "github.com",
    "bbc.co.uk",
    "kuwaitnews.com",
    # traps
    "kibana.io",
    "mohammed.com",
    "pacific.com",
    "moisture.com",
    "stcoupon.com",
    "zainab.com",
    "knetwork.com",
    "nbc.com",
    "abc.com",
    "mom.com",
    "kuwait.com",
    "kuwait-jobs.com",
    "q8car.com",
    "steampowered.com",
    "purchase.com",
    # squats
    "nbk.xyz",
    "nbkk.com",
    "nkb.com",
    "nbk-login.com",
    "nbklogin.com",
    "nbk0nline.com",
    "nbк.com",
    "xn--nb-3lc.com",
    "nbk.com.verify-login.tk",
    "nbk.evil.com",
    "login-nbk-kw.top",
    "kfh-online.xyz",
    "kuwait-finance-house.com",
    "baitak-update.com",
    "knetpay.info",
    "knet-secure.xyz",
    "k-net.com",
    "kpay-kw.com",
    "moilogin.com",
    "moi-kw.com",
    "moi-fines.top",
    "moi-gov-kw.com",
    "paci-civilid.com",
    "sahel-app.com",
    "egov-kw.com",
    "bourgan.com",
    "burganbank.com",
    "gulfbank-login.com",
    "boubyan-verify.com",
    "warbabank.xyz",
    "zain-kw.com",
    "zainpay.com",
    "ooredoo-kw.top",
    "stc-kw.com",
    "stckw.com",
    "vivakw.com",
    "kuwaitairways-booking.com",
    "talabat-offers.com",
    "cbk-secure.com",
    "tijari-online.com",
    "xn----zmcb6dvcikfqw.com",
    "بيتك-تحديث.com",
    "nbk-secure-login.web.app",
    "nbk.com-secure.icu",
    "secure-nbk-com.ga",
    "nationalbankofkuwait.com",
    "wwwnbk.com",
    "nbkbank.com",
    "kfhh.com",
    "kfhbank.com",
    "nbk2024.com",
    "nbc-kuwait-login.top",
    "cbk-nbk-login.com",
    "abk-login.tk",
    "kib-secure.com",
    "nbk-xyzzy.com",
    "paypal-account-verify.com",
    "secure-update.ga",
    "x9q2z8k1m3w7v5p4.com",
    "a.b.c.d.this-is-a-very-long-suspicious-domain-name-targeting-kuwait123456.xyz",
    "http://192.168.1.10/login",
    "https://NBK-Login.xyz/verify",
    "*.nbk-verify.top",
    "bank.com",
    "kuwait-bank.tk",
]

NODE_HARNESS = r"""
const path = require("path");
require(path.join(process.argv[1], "demo", "engine-data.js"));
const KCW = require(path.join(process.argv[1], "demo", "engine.js"));
const corpus = JSON.parse(require("fs").readFileSync(0, "utf8"));
const detector = new KCW.PhishingDetector();
const analyzer = new KCW.DomainAnalyzer({ legitimateDomains: new KCW.BrandMonitor().protectedDomains() });
const monitor = new KCW.BrandMonitor({ dedupeWindowSeconds: 0 });
const out = {};
for (const d of corpus) {
  const v = detector.analyze(d);
  const parsed = KCW.parseDomain(d);
  out[d] = {
    parsed: { hostname: parsed.hostname, registrable: parsed.registrable, label: parsed.label, suffix: parsed.suffix,
              unicode_label: parsed.unicode_label, is_idn: parsed.is_idn, hosting_platform: parsed.hosting_platform, valid: parsed.valid },
    risk_score: v.risk_score, risk_level: v.risk_level, is_phishing: v.is_phishing,
    categories: v.categories, matched_brands: v.matched_brands,
    indicator_types: v.indicators.map((i) => i.type).sort(),
    analyzer: analyzer.analyze(d).map((r) => [r.target, r.attack_types.slice().sort(), r.risk_level]),
    monitor: monitor.checkDomain(d, "scan", false).map((a) => [a.brand_name, a.alert_type, a.severity]).sort(),
  };
}
process.stdout.write(JSON.stringify(out));
"""


def run_js(corpus):
    proc = subprocess.run(
        [NODE, "-e", NODE_HARNESS, str(ROOT)],
        input=json.dumps(corpus),
        capture_output=True,
        text=True,
        check=True,
        cwd=str(ROOT),
    )
    return json.loads(proc.stdout)


def python_results(corpus):
    from src.utils.domain import parse_domain

    detector = PhishingDetector()
    monitor = BrandMonitor(dedupe_window_seconds=0)
    analyzer = DomainAnalyzer(
        DomainAnalysisConfig(), legitimate_domains=monitor.protected_domains()
    )
    out = {}
    for d in corpus:
        v = detector.analyze(d)
        p = parse_domain(d)
        out[d] = {
            "parsed": {
                "hostname": p.hostname,
                "registrable": p.registrable,
                "label": p.label,
                "suffix": p.suffix,
                "unicode_label": p.unicode_label,
                "is_idn": p.is_idn,
                "hosting_platform": p.hosting_platform,
                "valid": p.valid,
            },
            "risk_score": v.risk_score,
            "risk_level": v.risk_level,
            "is_phishing": v.is_phishing,
            "categories": v.categories,
            "matched_brands": v.matched_brands,
            "indicator_types": sorted(i["type"] for i in v.indicators),
            "analyzer": [
                [r.target_domain, sorted(r.attack_types), r.risk_level] for r in analyzer.analyze(d)
            ],
            "monitor": sorted(
                [a.brand_name, a.alert_type, a.severity]
                for a in monitor.check_domain(d, record=False)
            ),
        }
    return out


def test_engine_data_is_current():
    """demo/engine-data.js must be regenerated whenever the Python tables change."""
    proc = subprocess.run(
        [sys.executable, "scripts/export_engine_data.py", "--check"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestParity:
    @pytest.fixture(scope="class")
    def results(self):
        return python_results(CORPUS), run_js(CORPUS)

    def test_parsing(self, results):
        py, js = results
        mismatches = {
            d: (py[d]["parsed"], js[d]["parsed"])
            for d in CORPUS
            if py[d]["parsed"] != js[d]["parsed"]
        }
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_phishing_verdicts(self, results):
        py, js = results
        keys = (
            "risk_score",
            "risk_level",
            "is_phishing",
            "categories",
            "matched_brands",
            "indicator_types",
        )
        mismatches = {}
        for d in CORPUS:
            diff = {k: (py[d][k], js[d][k]) for k in keys if py[d][k] != js[d][k]}
            if diff:
                mismatches[d] = diff
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_analyzer(self, results):
        py, js = results
        mismatches = {
            d: (py[d]["analyzer"], js[d]["analyzer"])
            for d in CORPUS
            if py[d]["analyzer"] != js[d]["analyzer"]
        }
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_brand_monitor(self, results):
        py, js = results
        mismatches = {
            d: (py[d]["monitor"], js[d]["monitor"])
            for d in CORPUS
            if py[d]["monitor"] != js[d]["monitor"]
        }
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_permutations_match(self):
        analyzer = DomainAnalyzer(DomainAnalysisConfig())
        py = analyzer.generate_permutations_detailed(
            "nbk.com", tlds=["com", "kw", "com.kw"], max_results=400
        )
        script = (
            'const path=require("path");require(path.join(process.argv[1],"demo","engine-data.js"));'
            'const KCW=require(path.join(process.argv[1],"demo","engine.js"));'
            "const a=new KCW.DomainAnalyzer();"
            'process.stdout.write(JSON.stringify(a.generatePermutationsDetailed("nbk.com",{tlds:["com","kw","com.kw"],maxResults:400})));'
        )
        js = json.loads(
            subprocess.run(
                [NODE, "-e", script, str(ROOT)], capture_output=True, text=True, check=True
            ).stdout
        )
        assert [(p["domain"], p["technique"]) for p in py] == [
            (p["domain"], p["technique"]) for p in js
        ]
