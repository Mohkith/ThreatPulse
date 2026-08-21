"""
ThreatPulse - Main Orchestrator

Runs the full pipeline: Scrape -> Enrich -> Filter -> Serve

Usage:
  python main.py                    # Run full pipeline + start dashboard
  python main.py --demo             # Demo mode with sample data
  python main.py --serve-only       # Only serve dashboard
  python main.py --serve-only --demo  # Serve demo dashboard
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(__file__))

PROJECT_ROOT = os.path.dirname(__file__)
DEMO_DIR = os.path.join(PROJECT_ROOT, "data", "demo")
SCRAPER_DIR = os.path.join(PROJECT_ROOT, "data", "scraper")


def ensure_dirs():
    os.makedirs(DEMO_DIR, exist_ok=True)
    os.makedirs(SCRAPER_DIR, exist_ok=True)


def load_demo_data():
    """Load sample data into data/demo/."""
    ensure_dirs()
    output_path = os.path.join(DEMO_DIR, "demo_raw.json")
    if os.path.exists(output_path):
        with open(output_path) as f:
            data = json.load(f)
        count = sum(len(v) for v in data.values()) if isinstance(data, dict) else len(data)
        print(f"[+] Loaded {count} demo records from {output_path}")
        return data

    print(f"[-] No demo data found at {output_path}")
    return None


def run_pipeline_on(data_dir):
    from pipeline.run_pipeline import run_pipeline
    return run_pipeline(data_dir)


def serve_dashboard():
    from dashboard.app import app
    print("\n[*] Starting ThreatPulse dashboard on http://localhost:5000")
    print("[*] Demo:    http://localhost:5000/?mode=demo")
    print("[*] Live:    http://localhost:5000/?mode=scraper")
    app.run(debug=True, port=5000, host="0.0.0.0")


def main():
    parser = argparse.ArgumentParser(description="ThreatPulse Orchestrator")
    parser.add_argument("--demo", action="store_true", help="Use sample data for demo")
    parser.add_argument("--serve-only", action="store_true", help="Only serve dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port")
    args = parser.parse_args()

    print("=" * 60)
    print("  ThreatPulse v0.1")
    print("  Multi-Source Threat Intelligence Aggregator")
    print("  Built for Into the Scrape-Verse Hackathon")
    print("=" * 60)

    ensure_dirs()

    if args.serve_only:
        serve_dashboard()
        return

    if args.demo:
        print("\n[*] Demo mode: loading sample data...")
        load_demo_data()
        print("\n[*] Running pipeline on demo data...")
        result = run_pipeline_on(DEMO_DIR)
    else:
        from scrapers.setup_scrapers import run_scrapers
        print("\n[*] Live mode: running scrapers...")
        run_scrapers()
        print("\n[*] Running pipeline on scraper data...")
        result = run_pipeline_on(SCRAPER_DIR)

    if result:
        print(f"\n[+] Pipeline complete. {len(result['filtered'])} threats match your stack.")

    serve_dashboard()


if __name__ == "__main__":
    main()
