#!/usr/bin/env python3
"""
Capture screenshots of the KWTCyberWatch dashboard for the README.

Usage:
    pip install playwright && playwright install chromium
    python scripts/screenshots.py                  # demo mode from demo/index.html
    python scripts/screenshots.py http://localhost:5000   # against a running API

Screenshots are written to docs/screenshots/ relative to the repository root.
"""

import asyncio
import sys
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
DEMO = (ROOT / "demo" / "index.html").resolve().as_uri()
OUT = ROOT / "docs" / "screenshots"

PAGES = [
    ("certstream", "03-certstream.png", 2500),
    ("scanner", "04-scanner.png", 0),
    ("brands", "05-brands.png", 300),
    ("alerts", "06-alerts.png", 300),
    ("threatintel", "07-threatintel.png", 300),
    ("notifications", "08-notifications.png", 300),
    ("analytics", "09-analytics.png", 300),
    ("sightings", "10-sightings.png", 300),
]


async def main(base_url: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1400, "height": 900})

        await page.goto(base_url)
        await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUT / "01-login.png"))
        print("✓ Login page")

        await page.click(".login-demo-btn")
        await page.wait_for_timeout(800)
        await page.screenshot(path=str(OUT / "02-dashboard.png"))
        print("✓ Dashboard")

        for page_id, filename, wait_ms in PAGES:
            await page.click(f'[data-page="{page_id}"]')
            if page_id == "scanner":
                await page.fill("#scanInput", "nbk-secure-login.xyz")
                await page.click(".scan-btn")
                await page.wait_for_timeout(1500)
            elif wait_ms:
                await page.wait_for_timeout(wait_ms)
            await page.screenshot(path=str(OUT / filename))
            print(f"✓ {page_id}")

        await browser.close()
        print(f"\nAll screenshots captured in {OUT}")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else DEMO))
