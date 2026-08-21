import json
import re
from datetime import datetime, timedelta


def load_tech_stack(path="config/techstack.json"):
    with open(path) as f:
        return json.load(f)


def matches_product(product_name, tech_stack):
    product_lower = product_name.lower()
    matches = []

    for category, items in tech_stack.items():
        if category in ("company", "last_updated"):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            item_lower = item.lower()
            if len(item) <= 3:
                pattern = r'\b' + re.escape(item_lower) + r'\b'
                if re.search(pattern, product_lower):
                    matches.append({"category": category, "product": item})
            else:
                if item_lower in product_lower or product_lower in item_lower:
                    matches.append({"category": category, "product": item})
    return matches


def matches_text(text, tech_stack):
    text_lower = text.lower()
    matches = []

    for category, items in tech_stack.items():
        if category in ("company", "last_updated"):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            item_lower = item.lower()
            if len(item) <= 3:
                pattern = r'\b' + re.escape(item_lower) + r'\b'
                if re.search(pattern, text_lower):
                    matches.append({"category": category, "product": item})
            else:
                if item_lower in text_lower:
                    matches.append({"category": category, "product": item})

    return matches


def score_relevance(matches):
    if not matches:
        return 0

    score = len(matches) * 10

    high_value_categories = {"software", "virtualization", "network_equipment"}
    for m in matches:
        if m["category"] in high_value_categories:
            score += 15

    return score


def filter_by_tech_stack(records, tech_stack=None):
    if tech_stack is None:
        tech_stack = load_tech_stack()
    elif isinstance(tech_stack, str):
        with open(tech_stack) as f:
            tech_stack = json.load(f)

    filtered = []

    for record in records:
        raw_products = record.get("affected_products", [])
        flat_products = []
        for p in raw_products:
            if isinstance(p, list):
                flat_products.extend([str(x) for x in p if x])
            elif p:
                flat_products.append(str(p))

        all_text = " ".join([
            record.get("title", ""),
            record.get("description", ""),
            record.get("description_nvd", ""),
            " ".join(flat_products),
            " ".join(record.get("cve_ids", []))
        ])

        record["affected_products"] = flat_products

        matches = matches_text(all_text, tech_stack)

        for product in flat_products:
            product_matches = matches_product(product, tech_stack)
            matches.extend(product_matches)

        unique_matches = []
        seen = set()
        for m in matches:
            key = (m["category"], m["product"])
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)

        if unique_matches:
            record["affected_tech"] = unique_matches
            record["relevance_score"] = score_relevance(unique_matches)
            filtered.append(record)

    filtered.sort(key=lambda x: (
        -x.get("relevance_score", 0),
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "": 4}.get(x.get("severity", ""), 4)
    ))

    return filtered


def categorize_by_severity(records):
    categories = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Unknown": []
    }

    for record in records:
        severity = record.get("severity", "")
        if severity in categories:
            categories[severity].append(record)
        else:
            categories["Unknown"].append(record)

    return categories


def categorize_by_product(records):
    by_product = {}
    for record in records:
        for tech in record.get("affected_tech", []):
            product = tech["product"]
            if product not in by_product:
                by_product[product] = []
            by_product[product].append(record)
    return by_product


def generate_summary(filtered_records):
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    kev_count = 0
    products_affected = set()
    sources = set()

    for record in filtered_records:
        sev = record.get("severity", "")
        if sev in severity_counts:
            severity_counts[sev] += 1
        if record.get("kev_status"):
            kev_count += 1
        for tech in record.get("affected_tech", []):
            products_affected.add(tech["product"])
        sources.add(record.get("source", ""))

    return {
        "total_threats": len(filtered_records),
        "severity_breakdown": severity_counts,
        "kev_count": kev_count,
        "products_affected": list(products_affected),
        "sources": list(sources),
        "generated_at": datetime.utcnow().isoformat()
    }
