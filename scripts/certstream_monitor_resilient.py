#!/usr/bin/env python3
"""
KWTCyberWatch - Resilient CertStream Monitor
Real-time SSL/TLS certificate monitoring with automatic reconnection.

Enhanced version with exponential backoff retry mechanism for
production deployments.
"""

import certstream
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

KEYWORDS = ["kuwait", "kw", "kwt", "kwi", "q8"]
OUTPUT_FILE = "filtered_domains.txt"
INITIAL_RETRY_DELAY = 5
MAX_RETRY_DELAY = 300


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
    """Start the CertStream listener with retry logic."""
    retry_delay = INITIAL_RETRY_DELAY

    logger.info("Starting KWTCyberWatch Resilient CertStream monitor...")
    logger.info("Tracking keywords: %s", KEYWORDS)

    while True:
        try:
            logger.info("Connecting to CertStream...")
            certstream.listen_for_events(
                on_certificate_update,
                url="wss://certstream-server-domain/",
            )
            retry_delay = INITIAL_RETRY_DELAY
        except Exception as e:
            logger.error("Connection error: %s", e)
            logger.info("Retrying in %d seconds...", retry_delay)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)


if __name__ == "__main__":
    main()
