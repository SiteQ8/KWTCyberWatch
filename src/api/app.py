#!/usr/bin/env python3
"""
KWTCyberWatch - REST API Server
Flask-based API for the phishing detection suite.
"""

import os
import json
import logging
import functools
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from src.core.phishing_detector import PhishingDetector
from src.core.domain_analyzer import DomainAnalyzer
from src.core.brand_monitor import BrandMonitor
from src.config.settings import load_config

logger = logging.getLogger("kwtcyberwatch.api")

app = Flask(__name__, static_folder="../demo", static_url_path="/")
config = load_config()
CORS(app, origins=config.api.cors_origins)

# Initialize engines
phishing_detector = PhishingDetector(config)
domain_analyzer = DomainAnalyzer(config.domain_analysis)
brand_monitor = BrandMonitor()

# --- Authentication ---

DEMO_USERS = {
    "admin": {"password": "admin", "role": "admin", "name": "Administrator"},
    "analyst": {"password": "analyst", "role": "analyst", "name": "SOC Analyst"},
}


def require_api_key(f):
    """API key authentication decorator."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if config.api.api_key and api_key != config.api.api_key:
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated


# --- Routes ---

@app.route("/")
def index():
    """Serve the demo dashboard."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    """Demo authentication endpoint."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = DEMO_USERS.get(username)
    if user and user["password"] == password:
        return jsonify({
            "success": True,
            "user": {"username": username, "role": user["role"], "name": user["name"]},
            "token": f"demo-token-{username}-{datetime.now().timestamp():.0f}",
        })
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route("/api/v1/scan/domain", methods=["POST"])
def scan_domain():
    """Analyze a domain for phishing indicators."""
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    # Phishing analysis
    verdict = phishing_detector.analyze(domain)

    # Domain squatting analysis
    squat_results = domain_analyzer.analyze(domain)

    # Brand monitoring
    brand_alerts = brand_monitor.check_domain(domain)

    return jsonify({
        "domain": domain,
        "phishing": {
            "is_phishing": verdict.is_phishing,
            "confidence": verdict.confidence,
            "risk_score": verdict.risk_score,
            "risk_level": verdict.risk_level,
            "indicators": verdict.indicators,
            "categories": verdict.categories,
            "recommendation": verdict.recommendation,
        },
        "domain_squatting": [
            {
                "target": r.target_domain,
                "attack_types": r.attack_types,
                "similarity": r.similarity_score,
                "risk_level": r.risk_level,
            }
            for r in squat_results
        ],
        "brand_alerts": [
            {
                "alert_id": a.alert_id,
                "brand": a.brand_name,
                "type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
            }
            for a in brand_alerts
        ],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/v1/scan/bulk", methods=["POST"])
def scan_bulk():
    """Bulk domain analysis."""
    data = request.get_json() or {}
    domains = data.get("domains", [])

    if not domains or len(domains) > 100:
        return jsonify({"error": "Provide 1-100 domains"}), 400

    results = []
    for domain in domains:
        verdict = phishing_detector.analyze(domain.strip())
        results.append({
            "domain": domain,
            "risk_score": verdict.risk_score,
            "risk_level": verdict.risk_level,
            "is_phishing": verdict.is_phishing,
        })

    return jsonify({"results": results, "total": len(results)})


@app.route("/api/v1/brands", methods=["GET"])
def get_brands():
    """List all monitored brands."""
    return jsonify({
        "brands": [
            {
                "name": b.name,
                "domains": b.domains,
                "industry": b.industry,
                "priority": b.priority,
            }
            for b in brand_monitor.brands
        ]
    })


@app.route("/api/v1/brands/permutations", methods=["POST"])
def get_permutations():
    """Generate domain squatting permutations for a brand."""
    data = request.get_json() or {}
    brand = data.get("brand", "").strip()
    if not brand:
        return jsonify({"error": "Brand domain required"}), 400

    perms = domain_analyzer.generate_permutations(brand)
    return jsonify({"brand": brand, "permutations": perms[:200], "total": len(perms)})


@app.route("/api/v1/alerts", methods=["GET"])
def get_alerts():
    """Retrieve brand protection alerts."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    alerts = brand_monitor.get_alerts(status=status, severity=severity)
    return jsonify({
        "alerts": [
            {
                "alert_id": a.alert_id,
                "brand": a.brand_name,
                "type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
                "detected_at": a.detected_at,
                "status": a.status,
            }
            for a in alerts
        ],
        "total": len(alerts),
    })


@app.route("/api/v1/stats", methods=["GET"])
def get_stats():
    """Dashboard statistics."""
    return jsonify({
        "brands": brand_monitor.get_stats(),
        "detections": phishing_detector.detection_count,
        "uptime": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/v1/certstream/status", methods=["GET"])
def certstream_status():
    """CertStream monitor status."""
    return jsonify({
        "status": "active",
        "keywords": config.certstream.keywords,
        "url": config.certstream.url,
    })


@app.route("/api/v1/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "version": "2.0.0"})


def create_app():
    """Application factory."""
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(
        host=config.api.host,
        port=config.api.port,
        debug=config.api.debug,
    )
