"""Capture a screenshot of every page. Requires: pip install playwright && playwright install chromium
Start the app first:  streamlit run app.py --server.port 8501
"""
from pathlib import Path

from playwright.sync_api import sync_playwright

PAGES = {"overview": "Overview", "new-assessment": "New assessment", "attack-library": "Attack library",
         "test-history": "Test history", "analytics": "Vulnerability analytics", "reports": "Security reports", "settings": "Settings"}
OUT = Path(__file__).resolve().parent.parent / "assets" / "screenshots"

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto("http://localhost:8501")
    page.wait_for_selector("text=Overview")
    for slug, label in PAGES.items():
        page.get_by_text(label, exact=True).first.click()
        page.wait_for_timeout(1500)
        page.screenshot(path=str(OUT / f"{slug}.png"), full_page=True)
        print("saved", slug)
    browser.close()
