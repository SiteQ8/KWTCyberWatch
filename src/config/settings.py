#!/usr/bin/env python3
"""
KWTCyberWatch - Configuration Settings
Central configuration management for all modules.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class CertStreamConfig:
    """CertStream monitoring configuration."""
    url: str = "wss://certstream.calidog.io/"
    keywords: List[str] = field(default_factory=lambda: [
        "kuwait", "kw", "kwt", "kwi", "q8", "nbk", "kfh", "cbk",
        "burgan", "gulf-bank", "warba", "boubyan", "ahli-united",
        "zain-kw", "ooredoo-kw", "stc-kw", "moi-kw", "mofa-kw",
        "paci-kw", "moh-kw", "e-gov-kw"
    ])
    retry_delay: int = 5
    max_delay: int = 300
    log_file: str = "data/certstream_domains.log"


@dataclass
class DomainAnalysisConfig:
    """Domain squatting analysis configuration."""
    protected_brands: List[str] = field(default_factory=lambda: [
        "nbk.com", "kfh.com", "cbk.gov.kw", "burgan.com",
        "e.gov.kw", "moi.gov.kw", "zain.com", "ooredoo.com.kw",
        "kuwaitairways.com", "knpc.com", "kpc.com.kw"
    ])
    homoglyph_threshold: float = 0.85
    levenshtein_threshold: int = 3
    entropy_threshold: float = 3.5
    enable_whois: bool = True
    enable_dns: bool = True


@dataclass
class NotificationConfig:
    """Notification system configuration."""
    email_enabled: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_recipients: List[str] = field(default_factory=list)

    slack_enabled: bool = False
    slack_webhook_url: str = ""
    slack_channel: str = "#phishing-alerts"

    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_secret: str = ""


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    secret_key: str = "change-me-in-production"
    api_key: str = ""
    rate_limit: str = "100/hour"
    cors_origins: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class DatabaseConfig:
    """Database configuration."""
    db_type: str = "sqlite"
    db_path: str = "data/kwtcyberwatch.db"
    connection_string: str = ""


@dataclass
class ThreatIntelConfig:
    """Threat intelligence configuration."""
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    shodan_api_key: str = ""
    abuseipdb_api_key: str = ""
    phishtank_api_key: str = ""
    openphish_enabled: bool = True
    google_safebrowsing_key: str = ""


@dataclass
class Settings:
    """Master configuration."""
    certstream: CertStreamConfig = field(default_factory=CertStreamConfig)
    domain_analysis: DomainAnalysisConfig = field(default_factory=DomainAnalysisConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    api: APIConfig = field(default_factory=APIConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    log_level: str = "INFO"
    data_dir: str = "data"


def load_config(config_path: str = "config.yaml") -> Settings:
    """Load configuration from YAML file with env var overrides."""
    settings = Settings()

    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        if "certstream" in data:
            for k, v in data["certstream"].items():
                if hasattr(settings.certstream, k):
                    setattr(settings.certstream, k, v)

        if "notifications" in data:
            for k, v in data["notifications"].items():
                if hasattr(settings.notifications, k):
                    setattr(settings.notifications, k, v)

        if "api" in data:
            for k, v in data["api"].items():
                if hasattr(settings.api, k):
                    setattr(settings.api, k, v)

        if "threat_intel" in data:
            for k, v in data["threat_intel"].items():
                if hasattr(settings.threat_intel, k):
                    setattr(settings.threat_intel, k, v)

    # Environment variable overrides
    env_map = {
        "KCW_VT_API_KEY": ("threat_intel", "virustotal_api_key"),
        "KCW_URLSCAN_KEY": ("threat_intel", "urlscan_api_key"),
        "KCW_SHODAN_KEY": ("threat_intel", "shodan_api_key"),
        "KCW_SLACK_WEBHOOK": ("notifications", "slack_webhook_url"),
        "KCW_TELEGRAM_TOKEN": ("notifications", "telegram_bot_token"),
        "KCW_TELEGRAM_CHAT": ("notifications", "telegram_chat_id"),
        "KCW_API_SECRET": ("api", "secret_key"),
        "KCW_API_KEY": ("api", "api_key"),
    }

    for env_var, (section, key) in env_map.items():
        val = os.environ.get(env_var)
        if val:
            section_obj = getattr(settings, section)
            setattr(section_obj, key, val)

    return settings
