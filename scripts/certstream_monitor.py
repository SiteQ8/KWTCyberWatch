#!/usr/bin/env python3
"""
KWTCyberWatch - CertStream Monitor
Real-time SSL/TLS certificate monitoring for Kuwait-related domains.

Watches Certificate Transparency logs for newly issued certificates
containing Kuwait-related keywords (kuwait, kw, kwt, kwi, q8).
"""

import certstream
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

KEYWORDS = ["kuwait", "kw", "kwt", "kwi", "q8"]
OUTPUT_FILE = "filtered_domains.txt"


def on_certificate_update(message, context):
    """Process certificate update messages from CertStream."""
    if message["message_type"] != "certificate_update":
        return

    all_domains = message["data"]["leaf_cert"]["all_domains"]

    for domain in all_domains:
        if any(keyword in domain.lower() for keyword in KEYWORDS):
            logger.info("Match found: %s", domain)
            with open(OUTPUT_FILE, "a") as f:
                f.write(domain + "\n")


def main():
    """Start the CertStream listener."""
    logger.info("Starting KWTCyberWatch CertStream monitor...")
    logger.info("Tracking keywords: %s", KEYWORDS)
    certstream.listen_for_events(on_certificate_update, url="wss://certstream-server-domain/")


if __name__ == "__main__":
    main()
