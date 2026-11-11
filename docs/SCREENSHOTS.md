# Generating screenshots

1. `streamlit run app.py`
2. On Overview click **Run demo assessment** (or run three assessments with different defence levels for richer charts).
3. Capture each page at about 1440x900 and save to `assets/screenshots/`:
   `overview.png`, `new-assessment.png`, `attack-library.png`, `test-history.png`, `analytics.png`, `reports.png`, `settings.png`.
4. Optional automation with Playwright:
   ```bash
   pip install playwright && playwright install chromium
   python scripts/capture_screenshots.py
   ```
