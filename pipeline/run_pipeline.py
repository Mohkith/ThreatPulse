import os
import json
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline.normalize import normalize_all
from pipeline.enrich import enrich_all
from pipeline.filter import filter_by_tech_stack, generate_summary, categorize_by_severity, categorize_by_product
from pipeline.database import save_filtered_batch, save_run_history, get_stats

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")


def load_raw_data(data_dir):
    raw_data = {}
    if not os.path.exists(data_dir):
        return raw_data
    for filename in os.listdir(data_dir):
        if filename.endswith("_raw.json"):
            scraper_id = filename.replace("_raw.json", "")
            filepath = os.path.join(data_dir, filename)
            with open(filepath) as f:
                data = json.load(f)
            if isinstance(data, list):
                raw_data[scraper_id] = data
            elif isinstance(data, dict):
                if "results" in data:
                    raw_data[scraper_id] = data["results"]
                elif "data" in data:
                    raw_data[scraper_id] = data["data"]
                elif any(isinstance(v, list) for v in data.values()):
                    raw_data.update(data)
                else:
                    raw_data[scraper_id] = [data]
    return raw_data


def run_pipeline(data_dir=None):
    if data_dir is None:
        data_dir = os.path.join(PROJECT_ROOT, "data", "scraper")

    print("=" * 60)
    print("  ThreatPulse Pipeline")
    print(f"  Data source: {data_dir}")
    print("=" * 60)

    print("\n[1/5] Loading raw scraper data...")
    raw_data = load_raw_data(data_dir)
    if not raw_data:
        print(f"  [-] No raw data found in {data_dir}")
        print("  [-] Run: python main.py (real mode) or python main.py --demo")
        return None
    print(f"  [+] Loaded data from {len(raw_data)} scrapers")

    print("\n[2/5] Normalizing records...")
    normalized = normalize_all(raw_data)
    print(f"  [+] {len(normalized)} unique records")

    print("\n[3/5] Filtering by tech stack (free, instant)...")
    techstack_path = os.path.join(CONFIG_DIR, "techstack.json")
    pre_filtered = filter_by_tech_stack(normalized, techstack_path)
    print(f"  [+] {len(pre_filtered)} match your stack (skipped {len(normalized) - len(pre_filtered)} irrelevant)")

    print("\n[4/5] Enriching only relevant records with NVD, CISA KEV, EPSS...")
    enriched = enrich_all(pre_filtered)

    filtered = enriched

    print("\n[5/6] Generating summary...")
    summary = generate_summary(filtered)
    severity = categorize_by_severity(filtered)
    by_product = categorize_by_product(filtered)

    print("\n[6/6] Saving to database...")
    new_count, updated_count = save_filtered_batch(filtered)
    save_run_history(
        total_scraped=sum(len(v) for v in raw_data.values()),
        total_normalized=len(normalized),
        total_relevant=len(filtered),
        new_threats=new_count,
        resolved_threats=0,
        summary=summary
    )
    print(f"  [+] DB: {new_count} new, {updated_count} updated")

    stats = get_stats()
    print(f"  [+] DB total: {stats['total_vulns']} vulns, {stats['relevant_vulns']} relevant, {stats['total_runs']} runs")

    enriched_path = os.path.join(data_dir, "enriched_filtered.json")
    with open(enriched_path, "w") as f:
        json.dump(filtered, f, indent=2, default=str)

    all_normalized_path = os.path.join(data_dir, "all_normalized.json")
    with open(all_normalized_path, "w") as f:
        json.dump(normalized, f, indent=2, default=str)

    filtered_path = os.path.join(data_dir, "filtered.json")
    with open(filtered_path, "w") as f:
        json.dump(filtered, f, indent=2, default=str)

    summary_path = os.path.join(data_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print("  Pipeline Complete")
    print("=" * 60)
    print(f"  Total threats relevant to your stack: {summary['total_threats']}")
    print(f"  Critical: {summary['severity_breakdown']['Critical']}")
    print(f"  High:     {summary['severity_breakdown']['High']}")
    print(f"  Medium:   {summary['severity_breakdown']['Medium']}")
    print(f"  Low:      {summary['severity_breakdown']['Low']}")
    print(f"  In CISA KEV: {summary['kev_count']}")
    print(f"  Products affected: {', '.join(summary['products_affected'])}")
    print("=" * 60)

    return {
        "filtered": filtered,
        "summary": summary,
        "severity": severity,
        "by_product": by_product
    }


if __name__ == "__main__":
    data_dir = sys.argv[1] if len(sys.argv) > 1 else None
    run_pipeline(data_dir)
