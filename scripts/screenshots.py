#!/usr/bin/env python3
"""Take screenshots of the KWTCyberWatch demo dashboard."""

import asyncio
from playwright.async_api import async_playwright

DEMO = "file:///home/claude/KWTCyberWatch/demo/index.html"
OUT = "/home/claude/KWTCyberWatch/docs/screenshots"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1400, "height": 900})

        # 1. Login page
        await page.goto(DEMO)
        await page.wait_for_timeout(500)
        await page.screenshot(path=f"{OUT}/01-login.png", full_page=False)
        print("✓ Login page")

        # 2. Login
        await page.fill("#loginUser", "admin")
        await page.fill("#loginPass", "admin")
        await page.click(".login-btn")
        await page.wait_for_timeout(800)

        # 3. Dashboard
        await page.screenshot(path=f"{OUT}/02-dashboard.png", full_page=False)
        print("✓ Dashboard")

        # 4. CertStream
        await page.click('[data-page="certstream"]')
        await page.wait_for_timeout(2500)
        await page.screenshot(path=f"{OUT}/03-certstream.png", full_page=False)
        print("✓ CertStream")

        # 5. Scanner
        await page.click('[data-page="scanner"]')
        await page.wait_for_timeout(300)
        await page.fill("#scanInput", "nbk-secure-login.xyz")
        await page.click(".scan-btn")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=f"{OUT}/04-scanner.png", full_page=False)
        print("✓ Scanner")

        # 6. Brand Monitor
        await page.click('[data-page="brands"]')
        await page.wait_for_timeout(300)
        await page.screenshot(path=f"{OUT}/05-brands.png", full_page=False)
        print("✓ Brands")

        # 7. Alerts
        await page.click('[data-page="alerts"]')
        await page.wait_for_timeout(300)
        await page.screenshot(path=f"{OUT}/06-alerts.png", full_page=False)
        print("✓ Alerts")

        # 8. Threat Intel
        await page.click('[data-page="threatintel"]')
        await page.wait_for_timeout(300)
        await page.screenshot(path=f"{OUT}/07-threatintel.png", full_page=False)
        print("✓ Threat Intel")

        # 9. Notifications
        await page.click('[data-page="notifications"]')
        await page.wait_for_timeout(300)
        await page.screenshot(path=f"{OUT}/08-notifications.png", full_page=False)
        print("✓ Notifications")

        # 10. Analytics
        await page.click('[data-page="analytics"]')
        await page.wait_for_timeout(300)
        await page.screenshot(path=f"{OUT}/09-analytics.png", full_page=False)
        print("✓ Analytics")

        await browser.close()
        print("\nAll screenshots captured!")

asyncio.run(main())
