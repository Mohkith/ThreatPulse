import json
import time
import requests
from datetime import datetime, timedelta


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"


_kev_cache = None
_epss_cache = None


def load_kev():
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        print(f"  [+] Loaded {len(_kev_cache)} KEV entries")
    except Exception as e:
        print(f"  [-] Failed to load KEV: {e}")
        _kev_cache = {}

    return _kev_cache


def load_epss_batch(cve_ids):
    global _epss_cache
    if _epss_cache is None:
        _epss_cache = {}

    uncached = [c for c in cve_ids if c not in _epss_cache]
    if not uncached:
        return _epss_cache

    batch_size = 100
    for i in range(0, len(uncached), batch_size):
        batch = uncached[i:i + batch_size]
        cve_param = ",".join(batch)
        try:
            resp = requests.get(EPSS_API, params={"cve": cve_param}, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("data", []):
                _epss_cache[item["cve"]] = {
                    "epss_score": item.get("epss"),
                    "percentile": item.get("percentile")
                }
            time.sleep(0.5)
        except Exception as e:
            print(f"  [-] EPSS batch failed: {e}")

    return _epss_cache


_nvd_cache = {}

def enrich_from_nvd(cve_id, retries=2):
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]
    for attempt in range(retries + 1):
        try:
            resp = requests.get(
                NVD_API,
                params={"cveId": cve_id},
                headers={"Accept": "application/json"},
                timeout=15
            )
            if resp.status_code == 429:
                wait = 3 * (attempt + 1)
                print(f"  [retry] NVD 429, waiting {wait}s...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {}

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            cvss = None
            cvss_vector = ""
            severity = ""

            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics and metrics[version_key]:
                    cvss_data = metrics[version_key][0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString", "")
                    severity = cvss_data.get("baseSeverity", metrics[version_key][0].get("baseSeverity", ""))
                    break

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc["value"])

            references = cve_data.get("references", [])
            remediation = ""
            for ref in references:
                tags = ref.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    remediation = ref.get("url", "")
                    break

            published = cve_data.get("published", "")

            result = {
                "cvss_score": cvss,
                "cvss_vector": cvss_vector,
                "severity": severity_from_score(cvss) if cvss else severity,
                "description_nvd": description,
                "cwe_ids": list(set(cwe_ids)),
                "remediation": remediation,
                "nvd_published": published,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }
            _nvd_cache[cve_id] = result
            return result
        except Exception as e:
            print(f"  [-] NVD lookup failed for {cve_id}: {e}")
            return {}


def severity_from_score(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def enrich_record(record, kev_data, epss_data):
    if record.get("cvss_score"):
        try:
            record["cvss_score"] = float(record["cvss_score"])
        except (ValueError, TypeError):
            record["cvss_score"] = None

    for cve_id in record.get("cve_ids", []):
        if cve_id in kev_data:
            record["kev_status"] = True
            kev_entry = kev_data[cve_id]
            if not record.get("remediation"):
                record["remediation"] = kev_entry.get("requiredAction", "")
            if not record.get("published_date"):
                record["published_date"] = kev_entry.get("dateAdded", "")

        if cve_id in epss_data:
            epss_info = epss_data[cve_id]
            try:
                record["epss_score"] = float(epss_info.get("epss_score", 0))
            except (ValueError, TypeError):
                record["epss_score"] = None
            try:
                record["epss_percentile"] = float(epss_info.get("percentile", 0))
            except (ValueError, TypeError):
                record["epss_percentile"] = None

    all_cves = record.get("cve_ids", [])
    if all_cves and not record.get("cvss_score"):
        nvd_data = enrich_from_nvd(all_cves[0])
        if nvd_data:
            for key, value in nvd_data.items():
                if value and not record.get(key):
                    record[key] = value
        time.sleep(3)

    if record.get("cvss_score"):
        record["severity"] = severity_from_score(record["cvss_score"])

    return record


def enrich_all(records):
    print("[*] Loading CISA KEV data...")
    kev_data = load_kev()

    all_cves = []
    for r in records:
        all_cves.extend(r.get("cve_ids", []))
    all_cves = list(set(all_cves))

    print(f"[*] Loading EPSS scores for {len(all_cves)} CVEs...")
    epss_data = load_epss_batch(all_cves)

    print(f"[*] Enriching {len(records)} records...")
    enriched = []
    for i, record in enumerate(records):
        enriched_record = enrich_record(record, kev_data, epss_data)
        enriched.append(enriched_record)
        if (i + 1) % 10 == 0:
            print(f"  Enriched {i + 1}/{len(records)}")

    print(f"[+] Enrichment complete. {len(enriched)} records processed.")
    return enriched
