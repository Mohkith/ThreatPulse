import json
import re
from datetime import datetime


UNIFIED_SCHEMA = {
    "cve_ids": [],
    "title": "",
    "description": "",
    "severity": "",
    "cvss_score": None,
    "cvss_vector": "",
    "affected_products": [],
    "affected_versions": [],
    "published_date": "",
    "source": "",
    "source_url": "",
    "kev_status": False,
    "epss_score": None,
    "cwe_ids": [],
    "attack_vector": "",
    "remediation": "",
    "tags": [],
    "scraped_at": ""
}


def extract_cve_ids(text):
    if not text:
        return []
    pattern = r'CVE-\d{4}-\d{4,}'
    return list(set(re.findall(pattern, text.upper())))


def extract_severity(text):
    if not text:
        return ""
    text_lower = text.lower()
    if "critical" in text_lower:
        return "Critical"
    if "high" in text_lower:
        return "High"
    if "medium" in text_lower or "moderate" in text_lower:
        return "Medium"
    if "low" in text_lower:
        return "Low"
    return ""


def normalize_thn(raw_items):
    normalized = []
    for item in raw_items:
        record = UNIFIED_SCHEMA.copy()
        record["title"] = item.get("title", "")
        record["description"] = item.get("description", item.get("snippet", ""))
        record["source_url"] = item.get("product_page_url", item.get("url", ""))
        record["source"] = "TheHackerNews"
        record["published_date"] = item.get("published_date", item.get("date", ""))
        record["scraped_at"] = datetime.utcnow().isoformat()
        record["tags"] = item.get("category_tags", item.get("tags", []))

        all_text = f"{record['title']} {record['description']} {item.get('description', '')}"
        record["cve_ids"] = item.get("cve_ids", []) or extract_cve_ids(all_text)
        raw_products = item.get("affected_products", [])
        if isinstance(raw_products, str):
            record["affected_products"] = [raw_products] if raw_products else []
        elif isinstance(raw_products, list):
            flat = []
            for p in raw_products:
                if isinstance(p, list):
                    flat.extend([str(x) for x in p if x])
                elif p:
                    flat.append(str(p))
            record["affected_products"] = flat
        else:
            record["affected_products"] = []
        record["severity"] = extract_severity(all_text)

        if item.get("cvss_score"):
            try:
                record["cvss_score"] = float(item["cvss_score"])
            except (ValueError, TypeError):
                pass

        normalized.append(record)
    return normalized


def normalize_fortinet(raw_items):
    normalized = []
    for item in raw_items:
        record = UNIFIED_SCHEMA.copy()
        record["title"] = item.get("advisory_title", item.get("title", ""))
        record["description"] = item.get("summary", item.get("description", ""))
        record["source_url"] = item.get("advisory_url", item.get("product_page_url", item.get("url", "")))
        record["source"] = "Fortinet PSIRT"
        record["published_date"] = item.get("published_date", item.get("date", ""))
        record["scraped_at"] = datetime.utcnow().isoformat()
        record["severity"] = item.get("severity", "")

        all_text = f"{record['title']} {record['description']}"
        record["cve_ids"] = item.get("cve_ids", []) or extract_cve_ids(all_text)

        raw_products = item.get("affected_products", [])
        flat_products = []
        for p in raw_products:
            if isinstance(p, dict):
                pname = p.get("product_version", p.get("product", ""))
                if pname:
                    flat_products.append(pname)
            elif isinstance(p, str):
                flat_products.append(p)
            elif isinstance(p, list):
                flat_products.extend([str(x) for x in p if x])
        record["affected_products"] = flat_products

        normalized.append(record)
    return normalized


def normalize_generic(raw_items):
    normalized = []
    for item in raw_items:
        record = UNIFIED_SCHEMA.copy()
        record["title"] = item.get("title", "")
        record["description"] = item.get("description", item.get("snippet", ""))
        record["source_url"] = item.get("url", item.get("product_page_url", ""))
        record["source"] = item.get("source", item.get("source_domain", "Web Search"))
        record["published_date"] = item.get("date", item.get("published_date", ""))
        record["scraped_at"] = datetime.utcnow().isoformat()

        all_text = f"{record['title']} {record['description']}"
        record["cve_ids"] = item.get("cve_ids", []) or extract_cve_ids(all_text)
        record["severity"] = item.get("severity", extract_severity(all_text))

        normalized.append(record)
    return normalized


NORMALIZERS = {
    "thn_vulns": normalize_thn,
    "fortinet_psirt": normalize_fortinet,
    "web_vuln_search": normalize_generic,
}


def normalize_all(raw_data_by_scraper):
    all_records = []
    for scraper_id, raw_items in raw_data_by_scraper.items():
        normalizer = NORMALIZERS.get(scraper_id, normalize_generic)
        normalized = normalizer(raw_items)
        all_records.extend(normalized)
    return deduplicate(all_records)


def deduplicate(records):
    by_cve = {}
    no_cve = []

    for record in records:
        if record["cve_ids"]:
            primary_cve = record["cve_ids"][0]
            if primary_cve in by_cve:
                existing = by_cve[primary_cve]
                if record["cvss_score"] and (not existing["cvss_score"] or record["cvss_score"] > existing["cvss_score"]):
                    existing["cvss_score"] = record["cvss_score"]
                existing["source"] = f"{existing['source']}, {record['source']}"
                existing["source_url"] = record["source_url"] if record["source_url"] else existing["source_url"]
                all_cves = list(set(existing["cve_ids"] + record["cve_ids"]))
                existing["cve_ids"] = all_cves
                existing["affected_products"] = list(set(
                    [p for p in existing["affected_products"] if p] +
                    [p for p in record["affected_products"] if p]
                ))
            else:
                by_cve[primary_cve] = record
        else:
            no_cve.append(record)

    return list(by_cve.values()) + no_cve


def normalize_file(filepath):
    with open(filepath) as f:
        data = json.load(f)

    if isinstance(data, list):
        raw_data = {"unknown": data}
    else:
        raw_data = data

    return normalize_all(raw_data)
