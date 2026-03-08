"""
KWTCyberWatch - Web Dashboard Application
Real-time Kuwait domain certificate monitoring dashboard.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
import os
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "kwt-cyberwatch-dev-key-change-in-prod")

# Demo credentials
DEMO_USERNAME = "admin"
DEMO_PASSWORD = "CyberWatch2024!"

# Sample monitoring data for demo
SAMPLE_ALERTS = [
    {
        "id": 1,
        "domain": "kuwait-bank-secure.com",
        "issuer": "Let's Encrypt",
        "risk": "high",
        "timestamp": "2026-03-08 14:23:01",
        "status": "new",
        "category": "Phishing",
    },
    {
        "id": 2,
        "domain": "kw-government-portal.net",
        "issuer": "Comodo",
        "risk": "critical",
        "timestamp": "2026-03-08 13:45:22",
        "status": "investigating",
        "category": "Impersonation",
    },
    {
        "id": 3,
        "domain": "q8-shopping-deals.com",
        "issuer": "Let's Encrypt",
        "risk": "medium",
        "timestamp": "2026-03-08 12:10:55",
        "status": "new",
        "category": "Suspicious",
    },
    {
        "id": 4,
        "domain": "kwt-telecom-update.org",
        "issuer": "DigiCert",
        "risk": "high",
        "timestamp": "2026-03-08 11:30:18",
        "status": "resolved",
        "category": "Phishing",
    },
    {
        "id": 5,
        "domain": "kuwait-airways-promo.com",
        "issuer": "Let's Encrypt",
        "risk": "critical",
        "timestamp": "2026-03-08 10:15:44",
        "status": "new",
        "category": "Brand Abuse",
    },
    {
        "id": 6,
        "domain": "kw-visa-services.net",
        "issuer": "GoDaddy",
        "risk": "high",
        "timestamp": "2026-03-08 09:52:33",
        "status": "investigating",
        "category": "Fraud",
    },
    {
        "id": 7,
        "domain": "q8-crypto-invest.io",
        "issuer": "Let's Encrypt",
        "risk": "medium",
        "timestamp": "2026-03-08 08:40:11",
        "status": "new",
        "category": "Scam",
    },
    {
        "id": 8,
        "domain": "kwi-ministry-login.com",
        "issuer": "Sectigo",
        "risk": "critical",
        "timestamp": "2026-03-08 07:20:05",
        "status": "new",
        "category": "Impersonation",
    },
]

SAMPLE_STATS = {
    "total_monitored": 14832,
    "alerts_today": 23,
    "critical_alerts": 5,
    "domains_blocked": 189,
    "uptime": "99.97%",
    "keywords_tracked": ["kuwait", "kw", "kwt", "kwi", "q8"],
}


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    if "logged_in" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USERNAME and password == DEMO_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please try again.", "error")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        alerts=SAMPLE_ALERTS,
        stats=SAMPLE_STATS,
        username=session.get("username", "admin"),
    )


@app.route("/alerts")
@login_required
def alerts():
    return render_template(
        "alerts.html",
        alerts=SAMPLE_ALERTS,
        username=session.get("username", "admin"),
    )


@app.route("/monitoring")
@login_required
def monitoring():
    return render_template(
        "monitoring.html",
        stats=SAMPLE_STATS,
        username=session.get("username", "admin"),
    )


@app.route("/settings")
@login_required
def settings():
    return render_template(
        "settings.html",
        stats=SAMPLE_STATS,
        username=session.get("username", "admin"),
    )


@app.route("/api/alerts")
@login_required
def api_alerts():
    return jsonify(SAMPLE_ALERTS)


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(SAMPLE_STATS)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
