#!/usr/bin/env python3
"""Real-browser validator for the FM-Browser SPA (run on the shutter LXC).

Usage:  /root/fmbpw/bin/python validate.py [URL] [SEARCH_TERM]
Default URL http://192.168.7.227:8899/ , default search 'github'.

Drives the system Chromium headless, asserts the in-browser-Babel SPA compiled
(no pageerror), runs a search, expands a row, and screenshots each step into
/workspace/shots (= /mnt/cephfs/shared/projects/shutter/shots on the host).
Add feature-specific checks where marked. Prints a JSON report.
"""
import json, os, sys
from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.7.227:8899/"
TERM = sys.argv[2] if len(sys.argv) > 2 else "github"
SHOTS = "/workspace/shots"; os.makedirs(SHOTS, exist_ok=True)
errors, console, report = [], [], {"url": URL}

with sync_playwright() as pw:
    browser = pw.chromium.launch(executable_path="/bin/chromium", headless=True,
                                 args=["--no-sandbox", "--disable-dev-shm-usage"])
    page = browser.new_page(viewport={"width": 1500, "height": 950})
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: console.append(f"{m.type}:{m.text}") if m.type in ("error", "warning") else None)
    try:
        page.goto(URL, wait_until="networkidle", timeout=45000)
        page.wait_for_selector("input", timeout=30000)   # SPA rendered
        page.wait_for_timeout(1500)
        page.screenshot(path=f"{SHOTS}/01_loaded.png")
        body = page.inner_text("body")
        report["spa_rendered"] = ("Search" in body and "Explore" in body)
        report["pageerrors"] = errors[:5]

        inp = page.locator("input").first
        inp.click(); inp.fill(TERM)
        page.wait_for_timeout(2500)
        rows = page.locator("table tbody tr")
        report["result_rows"] = rows.count()
        page.screenshot(path=f"{SHOTS}/02_results.png")
        if rows.count():
            rows.first.click()
            page.wait_for_timeout(800)
            page.screenshot(path=f"{SHOTS}/03_detail.png")

        # ----- FEATURE-SPECIFIC CHECKS: add assertions for your change here -----
        # Example (UA-7 pivots): locate by unique title, click, confirm state change.
        host_pivot = page.locator('[title*="Pivot: visits to this host"]')
        if host_pivot.count():
            before = page.locator("table tbody tr").count()
            host_pivot.first.click(); page.wait_for_timeout(1800)
            report["ua7_host_pivot"] = {"present": True, "rows_before": before,
                                        "rows_after": page.locator("table tbody tr").count()}
            page.screenshot(path=f"{SHOTS}/04_pivoted.png")
        # -----------------------------------------------------------------------
    except Exception as e:
        report["error"] = str(e)
    finally:
        browser.close()

report["ok"] = bool(report.get("spa_rendered")) and not report.get("pageerrors") and "error" not in report
print(json.dumps(report, indent=2))
if console:
    print("CONSOLE(err/warn):", console[:8])
sys.exit(0 if report["ok"] else 1)
