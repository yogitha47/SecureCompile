"""End-to-end browser smoke test (manual: python tests/ui_smoke.py). Needs playwright + Chrome/Edge."""
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
URL = "http://127.0.0.1:5057"
failures = []


def check(name, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + name + (f" - {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(name)


server = subprocess.Popen(
    [sys.executable, "-c",
     "import sys; sys.path.insert(0,'.'); from app import app; app.run(port=5057)"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            urllib.request.urlopen(URL + "/api/status", timeout=1)
            break
        except Exception:
            time.sleep(0.3)
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="chrome")
        except Exception:
            browser = p.chromium.launch(channel="msedge")
        page = browser.new_page()
        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(URL)
        page.wait_for_selector("#evalBody table", timeout=5000)
        check("evaluation table rendered from report", page.locator("#evalBody table").count() >= 1)

        # empty submit -> error state
        page.click("#analyzeButton")
        page.wait_for_selector("#errorBox:not([hidden])")
        check("empty input shows error", "Paste or upload" in page.inner_text("#errorBox"))
        errors.clear()  # the browser logs the deliberate 400 above as a console error

        # vulnerable example
        page.select_option("#exampleSelect", "vulnerable")
        page.click("#analyzeButton")
        page.wait_for_selector(".finding")
        n_all = page.locator(".finding").count()
        check("multiple findings displayed", n_all >= 5, str(n_all))
        check("engine provenance chips shown", page.locator(".finding .chip.engine").count() >= n_all)
        check("ML shown as unavailable or ok (not faked)", "ML:" in page.inner_text("#engineStrip"))
        page.select_option("#filterSeverity", "HIGH")
        n_high = page.locator(".finding").count()
        check("severity filter narrows list", 0 < n_high <= n_all)
        page.select_option("#filterSeverity", "")
        page.fill("#filterSearch", "strcpy")
        check("search filter works", 0 < page.locator(".finding").count() < n_all)
        page.click("#filterClear")
        check("clear filters restores list", page.locator(".finding").count() == n_all)

        # individual fix
        gets_card = page.locator(".finding", has_text="gets").first
        gets_card.get_by_text("Fix this issue").click()
        page.wait_for_selector("#fixPanel .diff")
        check("single fix shows diff", "fgets" in page.inner_text("#fixPanel .diff"))
        check("validation checks listed", page.locator("#fixPanel .check").count() >= 3)
        original = page.input_value("#codeInput")
        page.get_by_text("Reject proposal").click()
        check("reject leaves editor unchanged", page.input_value("#codeInput") == original)

        # whole program correction -> apply -> restore
        page.click("#fixAllButton")
        page.wait_for_selector("#fixPanel .diff")
        check("full correction shows validation status", "Validation:" in page.inner_text("#fixPanel"))
        page.get_by_text("Apply to editor").click()
        page.wait_for_function("document.getElementById('restoreButton').hidden === false")
        check("applied code differs from original", page.input_value("#codeInput") != original)
        page.wait_for_selector("#statusPill")
        page.click("#restoreButton")
        check("restore returns exact original", page.input_value("#codeInput") == original)

        # syntax example
        page.select_option("#exampleSelect", "syntax")
        page.click("#analyzeButton")
        page.wait_for_selector("#syntaxPanel:not([hidden])")
        check("syntax diagnostics panel shown separately", "Missing ';'" in page.inner_text("#syntaxPanel"))
        check("security finding still reported after syntax errors", page.locator(".finding").count() >= 1)

        # safe example
        page.select_option("#exampleSelect", "safe")
        page.click("#analyzeButton")
        page.wait_for_selector("#engineStrip:not([hidden])")
        page.wait_for_function("!document.getElementById('loadingBox').offsetParent")
        check("safe example has no rule-based findings", page.locator(".finding:not(.ml-origin)").count() == 0)
        # The Juliet-trained model may still flag it; that must appear as an ML-only lead, never as a rule finding.
        for card in page.locator(".finding.ml-origin").all():
            check("ML-only lead is labelled as such", "ML only" in card.inner_text())

        # report download
        page.select_option("#exampleSelect", "vulnerable")
        page.click("#analyzeButton")
        page.wait_for_selector(".finding")
        with page.expect_download() as d:
            page.click("#downloadButton")
        check("report downloads", d.value.suggested_filename == "securecompile_report.json")
        check("no console errors", not errors, "; ".join(errors))
        browser.close()
finally:
    server.terminate()

print("FAILED: " + ", ".join(failures) if failures else "ALL UI CHECKS PASSED")
sys.exit(1 if failures else 0)
