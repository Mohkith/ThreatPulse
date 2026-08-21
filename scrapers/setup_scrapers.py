"""
ThreatPulse - Bright Data Scraper Setup

Correct CLI syntax:
  bdata scraper create <url> <description>    # Create
  bdata scraper run <collector_id> [url]      # Run
  bdata scraper heal <collector_id> <prompt>  # Heal

Usage:
  python setup_scrapers.py --create       # Create all scrapers
  python setup_scrapers.py --run          # Run all scrapers
  python setup_scrapers.py --heal <id>    # Heal a specific scraper
  python setup_scrapers.py --list         # List created scrapers
"""

import json
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.database import should_run_scraper, save_scraper_run

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "scrapers.json")


def run_command(cmd):
    print(f"  > {cmd[:120]}...")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [-] Error: {result.stderr.strip()[:300]}")
        return None
    output = result.stdout.strip()
    if output:
        print(f"  [{output[:300]}]")
    return output


def create_scrapers():
    print("[*] Creating scrapers via Bright Data CLI...\n")

    scrapers = [
        {
            "id": "thn_vulns",
            "url": "https://thehackernews.com/search/label/Vulnerability",
            "name": "ThreatPulse THN Vulns",
            "description": "Extract all vulnerability articles: title, URL, publication date, category tags, article snippet. For each article also extract any CVE IDs (CVE-YYYY-NNNNN format), CVSS scores, and affected product names mentioned in the text."
        },
        {
            "id": "fortinet_psirt",
            "url": "https://fortiguard.com/psirt",
            "name": "ThreatPulse Fortinet PSIRT",
            "description": "Extract all Fortinet security advisories: advisory title, FG-IR ID, severity level, publication date, affected products, summary description, and link. Also extract any CVE IDs mentioned."
        },
        {
            "id": "web_vuln_search",
            "url": "https://www.google.com/search?q=critical+CVE+exploited+2026",
            "name": "ThreatPulse Web Vuln Search",
            "description": "Extract search results: page title, URL, snippet text, source domain. For each result extract any CVE IDs (CVE-YYYY-NNNNN), CVSS scores, severity levels, and affected product or vendor names."
        }
    ]

    created = {}

    for scraper in scrapers:
        print(f"--- Creating: {scraper['name']} ---")

        cmd = (
            f'bdata scraper create '
            f'"{scraper["url"]}" '
            f'"{scraper["description"]}" '
            f'--name "{scraper["name"]}" '
            f'--pretty'
        )

        output = run_command(cmd)
        if output:
            try:
                result = json.loads(output)
                collector_id = result.get("collector_id", "")
                status = result.get("status", "")
                created[scraper["id"]] = collector_id
                print(f"  [+] Collector ID: {collector_id} (status: {status})\n")
            except json.JSONDecodeError:
                created[scraper["id"]] = output
                print(f"  [+] Raw output saved\n")
        else:
            print(f"  [-] Failed to create {scraper['name']}\n")

    if created:
        with open(CONFIG_PATH) as f:
            config = json.load(f)

        for scraper_cfg in config.get("scrapers", []):
            if scraper_cfg["id"] in created:
                scraper_cfg["collector_id"] = created[scraper_cfg["id"]]

        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)

        print(f"\n[+] Updated {CONFIG_PATH} with collector IDs")

    print(f"\n[+] Created {len(created)}/{len(scrapers)} scrapers")
    return created


def run_one_scraper(scraper):
    collector_id = scraper.get("collector_id", "")
    if not collector_id:
        return scraper["id"], None, "no collector_id"

    url = scraper.get("url", "")
    if url:
        cmd = f'bdata scraper run {collector_id} {url} --pretty'
    else:
        cmd = f'bdata scraper run {collector_id} --pretty'

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout.strip() if result.returncode == 0 else None
    error = result.stderr.strip() if result.returncode != 0 else None
    return scraper["id"], output, error


def run_scrapers():
    print("[*] Running all scrapers in parallel (threads)...\n")

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    all_scrapers = [
        s for s in config.get("scrapers", [])
        if s.get("collector_id")
    ]

    if not all_scrapers:
        print("  [-] No scrapers with collector_id found (run --create first)")
        return {}

    to_run = []
    skipped = []
    for s in all_scrapers:
        if should_run_scraper(s["id"], max_age_hours=24):
            to_run.append(s)
        else:
            skipped.append(s)
            print(f"  [skip] {s['name']}: last run < 24h ago")

    if not to_run:
        print("\n  [+] All scrapers are fresh. Nothing to run.")
        return {}

    print(f"\n  [*] Running {len(to_run)} scrapers ({len(skipped)} skipped)...\n")

    data_dir = os.path.join(PROJECT_ROOT, "data", "scraper")
    os.makedirs(data_dir, exist_ok=True)

    results = {}
    with ThreadPoolExecutor(max_workers=len(to_run)) as pool:
        futures = {pool.submit(run_one_scraper, s): s for s in to_run}

        for future in as_completed(futures):
            scraper_obj = futures[future]
            scraper_id, output, error = future.result()
            scraper_name = scraper_obj["name"]
            collector_id = scraper_obj["collector_id"]

            if error:
                print(f"  [-] {scraper_name}: {error[:200]}")
                save_scraper_run(scraper_id, collector_id, "failed", 0, None)
            elif output:
                results[scraper_id] = output
                output_path = os.path.join(data_dir, f"{scraper_id}_raw.json")
                try:
                    data = json.loads(output)
                    with open(output_path, "w") as f:
                        json.dump(data, f, indent=2)
                    count = len(data) if isinstance(data, list) else "?"
                    print(f"  [+] {scraper_name}: {count} records")
                    save_scraper_run(scraper_id, collector_id, "success",
                                     count if isinstance(count, int) else 0, data)
                except json.JSONDecodeError:
                    output_path = output_path.replace(".json", ".txt")
                    with open(output_path, "w") as f:
                        f.write(output)
                    print(f"  [+] {scraper_name}: raw output saved")
                    save_scraper_run(scraper_id, collector_id, "success_raw", 0, None)

    print(f"\n[+] {len(results)}/{len(to_run)} scrapers completed")
    return results


def heal_scraper(collector_id):
    print(f"[*] Healing scraper: {collector_id}\n")
    prompt = "The page layout has changed. Re-analyze the page structure and update selectors to extract the same data fields as before."
    cmd = f'bdata scraper heal {collector_id} "{prompt}" --pretty'
    output = run_command(cmd)
    if output:
        print(f"\n[+] Heal complete for {collector_id}")
    return output


def list_scrapers():
    print("[*] Listing your scrapers...\n")
    cmd = "bdata scraper list --pretty"
    output = run_command(cmd)
    return output


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ThreatPulse Scraper Setup")
    parser.add_argument("--create", action="store_true", help="Create scrapers")
    parser.add_argument("--run", action="store_true", help="Run scrapers")
    parser.add_argument("--heal", type=str, help="Heal a scraper by collector_id")
    parser.add_argument("--list", action="store_true", help="List scrapers")
    args = parser.parse_args()

    if args.create:
        create_scrapers()
    elif args.run:
        run_scrapers()
    elif args.heal:
        heal_scraper(args.heal)
    elif args.list:
        list_scrapers()
    else:
        parser.print_help()
