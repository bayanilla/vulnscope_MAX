#!/usr/bin/env python3
"""Browser smoke test for the Explorer pages (explorer.html).

Opens each report's explorer.html in headless Chromium and walks every view the page offers:
3D overview, focus on a host, Flat, Attack paths and Timeline. A report fails when

  * the page throws or logs a console error (any view), or
  * 3D draws fewer host bodies than there are hosts in the data, or three.js would draw fewer than it holds
    (the >1,024-host bug fixed in PR #23), or
  * the Timeline draws fewer chords than it has flows, or puts a chord end at no position.

Usage:
  python scripts/smoke/explorer_smoke.py --samples WORKDIR   analyze the bundled samples, one edge case (IOCs
                                                             with no article link) and the two-company
                                                             comparison into WORKDIR, then check them
  python scripts/smoke/explorer_smoke.py RUN [RUN ...]       check existing output folders (or explorer.html files)

Needs `pip install playwright` and a Chromium (`python -m playwright install chromium`). WebGL comes from
Chromium's software renderer, so no GPU is needed; a page that cannot start 3D fails rather than skipping it.
Screenshots of every view go to <WORKDIR or the first RUN's parent>/smoke-shots/ for looking at by eye.
"""
from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SINGLE_SAMPLES = ["scan_and_telemetry", "telemetry_only", "gootloader_seo_poisoning", "hosts_onprem_and_aws"]
SETTLE_MS = 1500      # time for a view to build and draw a few frames
# Chromium's software GL prints performance notes as console warnings; only errors count.


def build_samples(work: Path) -> list[Path]:
    """Analyze each bundled sample, plus the two-company Compare sample and its comparison."""
    work.mkdir(parents=True, exist_ok=True)
    runs = []
    for name in SINGLE_SAMPLES:
        out = work / name
        if not (out / "explorer.html").exists():
            subprocess.run([sys.executable, "-m", "vulnflow", "analyze", str(ROOT / "samples" / name), "-o", str(out)],
                           check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
        runs.append(out)
    runs.append(build_edge_case(work))
    data = work / "compare_data"
    if not data.exists():
        subprocess.run([sys.executable, "-m", "vulnflow", "compare-sample", "--data-dir", str(data)],
                       check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
    # the comparison's all-networks map, then one site report (the Gootloader HQ)
    pages = sorted(p.relative_to(data) for p in data.rglob("explorer.html"))
    runs += [data / p.parent for p in pages if p.parts[0] == "comparisons"][:1]
    runs += [data / p.parent for p in pages if p.parts[0].startswith("Ridgeline-HQ")][:1]
    return runs


def build_edge_case(work: Path) -> Path:
    """The Gootloader sample with the article links taken off its IOCs (an IOC CSV may have none):
    Attack paths crashed on that shape from PR #7 until #38."""
    out = work / "edge_iocs_without_articles"
    if (out / "explorer.html").exists():
        return out
    src = work / "edge_input"
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(ROOT / "samples" / "gootloader_seo_poisoning", src)
    (src / "article_previews.json").unlink(missing_ok=True)
    ioc = src / "ioc_indicators.csv"
    with ioc.open(newline="") as f:
        rows = list(csv.DictReader(f))
    with ioc.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows({**r, "articleUrls": ""} for r in rows)
    subprocess.run([sys.executable, "-m", "vulnflow", "analyze", str(src), "-o", str(out), "--no-article-preview"],
                   check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
    return out


def explorer_file(run: Path) -> Path:
    page = run if run.suffix == ".html" else run / "explorer.html"
    if not page.is_file():
        raise SystemExit(f"no explorer.html in {run}")
    return page


def check(page_path: Path, browser, shots: Path) -> list[str]:
    problems: list[str] = []
    label = page_path.parent.name if page_path.parent.name != "out" else page_path.parent.parent.name
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(f"uncaught: {e}"))
    page.on("console", lambda m: errors.append(f"console.error: {m.text}") if m.type == "error" else None)

    def step(name: str) -> None:
        page.wait_for_timeout(SETTLE_MS)
        page.screenshot(path=str(shots / f"{label}__{name}.png"))
        while errors:
            problems.append(f"{name}: {errors.pop(0)}")

    page.goto(page_path.resolve().as_uri() + "?3d")
    step("3d-overview")
    if not page.evaluate("!!window.VFExplorer"):
        page.close()
        return problems + ["page did not start (window.VFExplorer missing)"]
    if not page.evaluate("VFExplorer.can3d"):
        problems.append("3D unavailable in this browser (WebGL missing), so 3D was not checked")
    else:
        s = page.evaluate("VFExplorer.stats()")
        if not s.get("is3d"):
            problems.append(f"3d-overview: page did not open in 3D ({s})")
        elif s["bodies"] < s["hosts"] or s["bodiesDrawable"] < s["bodies"]:
            problems.append(f"3d-overview: {s['hosts']} hosts in the data, {s['bodies']} bodies added, "
                            f"{s['bodiesDrawable']} drawable")

    first = page.evaluate("JSON.parse(document.getElementById('vf-data').textContent).nodes.map(n => n.id)[0] ?? null")
    if first is not None:
        page.evaluate("id => VFExplorer.focus(id)", first)
        step("3d-focus")
        page.evaluate("VFExplorer.overview()")

    page.evaluate("VFExplorer.set3d(false)")
    step("flat")

    if page.evaluate("!!window.VFPaths && !document.getElementById('btn-paths').hidden"):
        page.click("#btn-paths")
        step("attack-paths")
        page.evaluate("VFPaths.close()")

    if page.evaluate("!!window.VFTimeline && !document.getElementById('btn-timeline').hidden"):
        page.click("#btn-timeline")
        step("timeline")
        t = page.evaluate("VFTimeline.stats()")
        if t["drawn"] != t["flows"] or t["misplaced"]:
            problems.append(f"timeline: {t['flows']} flows in the data, {t['drawn']} drawn, "
                            f"{t['misplaced']} chord ends with no position")
        page.evaluate("VFTimeline.close()")

    page.evaluate("VFExplorer.set3d(true)")
    step("back-to-3d")
    page.close()
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs", nargs="*", type=Path, help="output folders or explorer.html files")
    ap.add_argument("--samples", type=Path, metavar="WORKDIR", help="analyze the bundled samples into WORKDIR first")
    args = ap.parse_args()
    runs = list(args.runs)
    if args.samples:
        runs += build_samples(args.samples)
    if not runs:
        ap.error("give output folders or --samples WORKDIR")
    pages = [explorer_file(r) for r in runs]
    shots = (args.samples or pages[0].parent.parent) / "smoke-shots"
    shots.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright
    failed = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for p in pages:
            problems = check(p, browser, shots)
            print(("FAIL " if problems else "ok   ") + str(p))
            for line in problems:
                print("     - " + line)
            failed += bool(problems)
        browser.close()
    print(f"\n{len(pages) - failed} of {len(pages)} Explorer pages passed; screenshots in {shots}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
