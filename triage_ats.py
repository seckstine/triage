"""
triage_ats.py - fingerprint which ATS (applicant tracking system) platform
each company's career site runs on, BEFORE investing more per-company
debugging time like we did for 2sigma (Avature) and MLP (Eightfold).

Why this matters: several major ATS platforms expose a documented public
JSON API that needs zero reverse-engineering -- point at it and you're
done. Others need the kind of investigation this project already did for
Avature/Eightfold. This script tells you, up front, how many of your 30
companies fall into each bucket so you can batch the work by platform
instead of re-discovering everything company-by-company.

Usage:
    1. Fill in companies.csv with one row per company:
           name,url
           Acme Corp,https://acme.com/careers
           Beta Inc,
       (leave url blank to attempt auto-discovery via discover.py)

    2. Run:
           python triage_ats.py companies.csv

    3. Read triage_report.csv / the printed summary.

Detection is signature-based (URL host/query patterns + page content
markers for known platforms). It can misfire on unusual setups -- treat
"UNKNOWN" and low-confidence rows as needing a manual look, same as we
did for MLP originally.
"""

import csv
import re
import sys
import time
from urllib.parse import urlparse, parse_qs

import requests

USER_AGENT = "Mozilla/5.0 (compatible; JobScraperBot/1.0; +https://example.com/bot)"
TIMEOUT = 15

# Each entry: (platform name, detector function, has_public_api, api_note)
# detector(url, parsed_url, html_lower) -> True/False


def _host_has(parsed, *substrings):
    host = parsed.netloc.lower()
    return any(s in host for s in substrings)


def _html_has(html_lower, *substrings):
    return any(s in html_lower for s in substrings)


PLATFORMS = [
    (
        "Greenhouse",
        lambda url, p, h: _host_has(p, "greenhouse.io") or _html_has(h, "boards.greenhouse.io", "grnhse_app"),
        True,
        "Public API: https://boards-api.greenhouse.io/v1/boards/{board_token}/jobs "
        "-- board_token is usually in the URL path, e.g. boards.greenhouse.io/{token}.",
    ),
    (
        "Lever",
        lambda url, p, h: _host_has(p, "lever.co") or _html_has(h, "jobs.lever.co", "lever-jobs"),
        True,
        "Public API: https://api.lever.co/v0/postings/{company}?mode=json "
        "-- {company} is the slug in jobs.lever.co/{company}.",
    ),
    (
        "SmartRecruiters",
        lambda url, p, h: _host_has(p, "smartrecruiters.com") or _html_has(h, "smartrecruiters.com/careers"),
        True,
        "Public API: https://api.smartrecruiters.com/v1/companies/{company}/postings "
        "-- {company} is the slug in jobs.smartrecruiters.com/{company}.",
    ),
    (
        "Ashby",
        lambda url, p, h: _host_has(p, "ashbyhq.com") or _html_has(h, "jobs.ashbyhq.com"),
        True,
        "Public API: POST https://api.ashbyhq.com/posting-api/job-board/{company} "
        "-- see Ashby's public job board API docs.",
    ),
    (
        "Workable",
        lambda url, p, h: _host_has(p, "workable.com") or _html_has(h, "apply.workable.com"),
        True,
        "Public API: https://apply.workable.com/api/v1/widget/accounts/{company} "
        "(the 'widget' endpoint used by their own embeddable widget).",
    ),
    (
        "Recruitee",
        lambda url, p, h: _host_has(p, "recruitee.com"),
        True,
        "Public API: https://{company}.recruitee.com/api/offers/",
    ),
    (
        "Workday",
        lambda url, p, h: _host_has(p, "myworkdayjobs.com") or _html_has(h, "myworkdayjobs.com", "workday"),
        False,
        "No universally-documented public API, but most tenants expose an "
        "internal JSON endpoint at /wday/cxs/{tenant}/{site}/jobs that the "
        "page itself calls -- sniff network requests (like we did for MLP) "
        "to confirm per-tenant. High-value target: usually paginated JSON, "
        "same technique as fetch_eightfold_api_jobs().",
    ),
    (
        "Eightfold",
        lambda url, p, h: (
            ("domain=" in url and "pid=" in url)
            or _html_has(h, "eightfold.ai", "static.vscdn.net", "efsmartapplycontainer", "smartapplydata")
        ),
        False,
        "SOLVED in this project -- use scraper.fetch_eightfold_api_jobs(). "
        "Confirm the URL has 'domain' and 'pid' query params.",
    ),
    (
        "Avature",
        lambda url, p, h: _host_has(p, "avature.net") or _html_has(h, "avature.net", "data-avature"),
        False,
        "SOLVED in this project -- use render='interactive' with "
        "search/submit selectors, same pattern as 2sigma. Selectors are "
        "per-company; run debug_scrape.py --list-controls to find them.",
    ),
    (
        "iCIMS",
        lambda url, p, h: _host_has(p, "icims.com") or _html_has(h, "icims.com"),
        False,
        "No standard public API, but many iCIMS boards expose an XML/RSS "
        "feed (look for a '/xml' or rss link on the page) -- often easier "
        "than the JSON-API-sniffing approach.",
    ),
    (
        "SuccessFactors",
        lambda url, p, h: _host_has(p, "successfactors.com", "sapsf.com") or _html_has(h, "successfactors"),
        False,
        "SAP SuccessFactors -- typically needs the same network-sniffing "
        "approach we used for MLP; no universal public API.",
    ),
    (
        "Taleo",
        lambda url, p, h: _host_has(p, "taleo.net") or _html_has(h, "taleo.net"),
        False,
        "Older Oracle platform, often server-rendered (may work with plain "
        "render='auto'/'never' -- check before assuming JS rendering is needed).",
    ),
    (
        "BambooHR",
        lambda url, p, h: _host_has(p, "bamboohr.com") or _html_has(h, "bamboohr.com/jobs"),
        True,
        "Public API: https://{company}.bamboohr.com/careers/list "
        "(returns JSON; company subdomain in the URL).",
    ),
    (
        "Jobvite",
        lambda url, p, h: _host_has(p, "jobvite.com") or _html_has(h, "jobvite.com"),
        False,
        "No standard public API -- investigate per-company like MLP/2sigma.",
    ),
    (
        "Breezy HR",
        lambda url, p, h: _host_has(p, "breezy.hr"),
        True,
        "Public API: https://{company}.breezy.hr/json (JSON feed of open positions).",
    ),
    (
        "Personio",
        lambda url, p, h: _host_has(p, "personio.com", "personio.de"),
        True,
        "Public XML API: https://{company}.jobs.personio.com/xml -- "
        "structured feed, no scraping needed.",
    ),
    (
        "Paylocity",
        lambda url, p, h: _host_has(p, "paylocity.com") or _html_has(h, "recruiting.paylocity.com"),
        False,
        "No standard public API -- investigate per-company.",
    ),
    (
        "Phenom People",
        lambda url, p, h: _html_has(h, "phenompeople.com", "phenom.com") ,
        False,
        "Different platform from Eightfold despite similar 'domain='/'pid=' "
        "URL styling sometimes -- verify carefully, don't assume it's "
        "Eightfold just because the URL looks similar.",
    ),
]


def fetch(url):
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(url, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.text


def classify(url):
    parsed = urlparse(url)
    try:
        html = fetch(url)
        html_lower = html.lower()
        fetch_ok = True
        fetch_error = None
    except Exception as e:
        html_lower = ""
        fetch_ok = False
        fetch_error = str(e)

    matches = []
    for platform, detector, has_api, note in PLATFORMS:
        try:
            if detector(url, parsed, html_lower):
                matches.append((platform, has_api, note))
        except Exception:
            continue

    return {
        "fetch_ok": fetch_ok,
        "fetch_error": fetch_error,
        "matches": matches,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python triage_ats.py companies.csv")
        print("\ncompanies.csv format (header row required):")
        print("  name,url")
        print("  Acme Corp,https://acme.com/careers")
        print("  Beta Inc,")
        print("\n(leave url blank to attempt auto-discovery via discover.py)")
        sys.exit(1)

    csv_path = sys.argv[1]
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"Could not find '{csv_path}'.")
        sys.exit(1)

    if not rows:
        print("No rows found in the CSV.")
        sys.exit(1)

    # discover.py is optional -- only import it if we actually need
    # auto-discovery, so this script still works standalone otherwise.
    discover_fn = None

    results = []
    for row in rows:
        name = row.get("name", "").strip()
        url = (row.get("url") or "").strip()

        if not url:
            if discover_fn is None:
                try:
                    import discover as discover_module
                    discover_fn = discover_module.discover_careers_url
                except ImportError:
                    discover_fn = False
            if discover_fn:
                print(f"[{name}] No URL given, attempting auto-discovery...")
                url = discover_fn(name) or ""
                if url:
                    print(f"[{name}] Discovered: {url}")
                else:
                    print(f"[{name}] Could not auto-discover a careers URL. Skipping.")
                    results.append({"name": name, "url": "", "platform": "SKIPPED (no URL)",
                                     "has_public_api": "", "note": ""})
                    continue
            else:
                print(f"[{name}] No URL given and discover.py not available. Skipping.")
                results.append({"name": name, "url": "", "platform": "SKIPPED (no URL)",
                                 "has_public_api": "", "note": ""})
                continue

        print(f"[{name}] Fetching {url} ...")
        info = classify(url)

        if not info["fetch_ok"]:
            print(f"[{name}]   FETCH FAILED: {info['fetch_error']}")
            results.append({"name": name, "url": url, "platform": f"FETCH FAILED ({info['fetch_error']})",
                             "has_public_api": "", "note": ""})
            time.sleep(1)
            continue

        if not info["matches"]:
            print(f"[{name}]   No known platform signature matched -- UNKNOWN, needs manual investigation.")
            results.append({"name": name, "url": url, "platform": "UNKNOWN", "has_public_api": "", "note": ""})
        else:
            for platform, has_api, note in info["matches"]:
                api_tag = "YES (documented public API)" if has_api else "no (needs investigation)"
                print(f"[{name}]   -> {platform}  [public API: {api_tag}]")
                results.append({
                    "name": name, "url": url, "platform": platform,
                    "has_public_api": "yes" if has_api else "no", "note": note,
                })

        time.sleep(1)  # be polite

    # --- Write report ---
    out_path = "triage_report.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "url", "platform", "has_public_api", "note"])
        writer.writeheader()
        writer.writerows(results)

    # --- Summary ---
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    from collections import Counter
    platform_counts = Counter(r["platform"] for r in results)
    for platform, count in platform_counts.most_common():
        print(f"  {platform}: {count}")

    api_count = sum(1 for r in results if r["has_public_api"] == "yes")
    unknown_count = sum(1 for r in results if r["platform"] == "UNKNOWN")
    solved_count = sum(1 for r in results if r["platform"] in ("Avature", "Eightfold"))

    print(f"\n  Companies with a documented public API (easiest -- no scraping needed): {api_count}")
    print(f"  Companies on a platform this project already solved (Avature/Eightfold): {solved_count}")
    print(f"  Companies with UNKNOWN platform (need manual investigation): {unknown_count}")
    print(f"\nFull details written to {out_path}")
    print("\nPaste this summary (and triage_report.csv if you want a deeper look) back to Claude.")


if __name__ == "__main__":
    main()
