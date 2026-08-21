"""
ThreatPulse - SQLite Database Layer

Minimal schema storing only useful fields.
Fast reads via indexes, batch writes via transactions.
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(PROJECT_ROOT, "data", "threatpulse.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scraper_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scraper_id TEXT NOT NULL,
            collector_id TEXT,
            run_at TEXT NOT NULL,
            status TEXT NOT NULL,
            records_count INTEGER DEFAULT 0,
            raw_data TEXT
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            title TEXT,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            affected_products TEXT,
            source TEXT,
            source_url TEXT,
            published_date TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            kev_status INTEGER DEFAULT 0,
            epss_score REAL,
            epss_percentile REAL,
            cwe_ids TEXT,
            remediation TEXT,
            tags TEXT,
            enriched_at TEXT
        );

        CREATE TABLE IF NOT EXISTS tech_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id INTEGER NOT NULL,
            category TEXT,
            product TEXT,
            relevance_score INTEGER DEFAULT 0,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS run_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_at TEXT NOT NULL,
            total_scraped INTEGER DEFAULT 0,
            total_normalized INTEGER DEFAULT 0,
            total_relevant INTEGER DEFAULT 0,
            new_threats INTEGER DEFAULT 0,
            resolved_threats INTEGER DEFAULT 0,
            summary TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vuln_last_seen ON vulnerabilities(last_seen);
        CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(kev_status);
        CREATE INDEX IF NOT EXISTS idx_tech_vuln ON tech_matches(vuln_id);
        CREATE INDEX IF NOT EXISTS idx_scraper_runs_at ON scraper_runs(run_at);
    """)
    conn.close()


def should_run_scraper(scraper_id, max_age_hours=24):
    conn = get_conn()
    row = conn.execute(
        "SELECT run_at FROM scraper_runs WHERE scraper_id = ? ORDER BY run_at DESC LIMIT 1",
        (scraper_id,)
    ).fetchone()
    conn.close()

    if not row:
        return True

    last_run = datetime.fromisoformat(row["run_at"])
    return (datetime.utcnow() - last_run).total_seconds() / 3600 > max_age_hours


def save_scraper_run(scraper_id, collector_id, status, records_count, raw_data):
    conn = get_conn()
    conn.execute(
        "INSERT INTO scraper_runs (scraper_id, collector_id, run_at, status, records_count, raw_data) VALUES (?, ?, ?, ?, ?, ?)",
        (scraper_id, collector_id, datetime.utcnow().isoformat(), status, records_count, json.dumps(raw_data) if raw_data else None)
    )
    conn.commit()
    conn.close()


def upsert_vulnerability(record):
    conn = get_conn()
    now = datetime.utcnow().isoformat()
    cve_id = record.get("cve_id", "")

    existing = conn.execute("SELECT id, first_seen FROM vulnerabilities WHERE cve_id = ?", (cve_id,)).fetchone()

    if existing:
        conn.execute("""
            UPDATE vulnerabilities SET
                title = COALESCE(?, title),
                description = COALESCE(?, description),
                severity = COALESCE(?, severity),
                cvss_score = COALESCE(?, cvss_score),
                cvss_vector = COALESCE(?, cvss_vector),
                affected_products = COALESCE(?, affected_products),
                source = COALESCE(?, source),
                source_url = COALESCE(?, source_url),
                published_date = COALESCE(?, published_date),
                last_seen = ?,
                kev_status = COALESCE(?, kev_status),
                epss_score = COALESCE(?, epss_score),
                epss_percentile = COALESCE(?, epss_percentile),
                cwe_ids = COALESCE(?, cwe_ids),
                remediation = COALESCE(?, remediation),
                tags = COALESCE(?, tags),
                enriched_at = COALESCE(?, enriched_at)
            WHERE cve_id = ?
        """, (
            record.get("title"), record.get("description"), record.get("severity"),
            record.get("cvss_score"), record.get("cvss_vector"),
            json.dumps(record.get("affected_products", [])),
            record.get("source"), record.get("source_url"), record.get("published_date"),
            now,
            1 if record.get("kev_status") else 0,
            record.get("epss_score"), record.get("epss_percentile"),
            json.dumps(record.get("cwe_ids", [])), record.get("remediation"),
            json.dumps(record.get("tags", [])), record.get("enriched_at"),
            cve_id
        ))
        vuln_id = existing["id"]
    else:
        cursor = conn.execute("""
            INSERT INTO vulnerabilities (
                cve_id, title, description, severity, cvss_score, cvss_vector,
                affected_products, source, source_url, published_date,
                first_seen, last_seen, kev_status, epss_score, epss_percentile,
                cwe_ids, remediation, tags, enriched_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id, record.get("title"), record.get("description"), record.get("severity"),
            record.get("cvss_score"), record.get("cvss_vector"),
            json.dumps(record.get("affected_products", [])),
            record.get("source"), record.get("source_url"), record.get("published_date"),
            now, now,
            1 if record.get("kev_status") else 0,
            record.get("epss_score"), record.get("epss_percentile"),
            json.dumps(record.get("cwe_ids", [])), record.get("remediation"),
            json.dumps(record.get("tags", [])), record.get("enriched_at")
        ))
        vuln_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return vuln_id


def save_tech_matches(vuln_id, matches):
    conn = get_conn()
    conn.execute("DELETE FROM tech_matches WHERE vuln_id = ?", (vuln_id,))
    for match in matches:
        conn.execute(
            "INSERT INTO tech_matches (vuln_id, category, product, relevance_score) VALUES (?, ?, ?, ?)",
            (vuln_id, match.get("category", ""), match.get("product", ""), match.get("score", 0))
        )
    conn.commit()
    conn.close()


def save_filtered_batch(records):
    conn = get_conn()
    now = datetime.utcnow().isoformat()
    new_count = 0
    updated_count = 0

    for record in records:
        cve_ids = record.get("cve_ids", [])
        if not cve_ids:
            cve_id = record.get("cve_id", "")
            if cve_id:
                cve_ids = [cve_id]

        if not cve_ids:
            continue

        primary_cve = cve_ids[0]

        existing = conn.execute("SELECT id FROM vulnerabilities WHERE cve_id = ?", (primary_cve,)).fetchone()

        if existing:
            updated_count += 1
            conn.execute("""
                UPDATE vulnerabilities SET
                    title = COALESCE(?, title),
                    description = COALESCE(?, description),
                    severity = COALESCE(?, severity),
                    cvss_score = COALESCE(?, cvss_score),
                    affected_products = COALESCE(?, affected_products),
                    source = COALESCE(?, source),
                    source_url = COALESCE(?, source_url),
                    last_seen = ?,
                    kev_status = COALESCE(?, kev_status),
                    epss_score = COALESCE(?, epss_score),
                    epss_percentile = COALESCE(?, epss_percentile),
                    remediation = COALESCE(?, remediation),
                    enriched_at = COALESCE(?, enriched_at)
                WHERE cve_id = ?
            """, (
                record.get("title"), record.get("description"), record.get("severity"),
                record.get("cvss_score"), json.dumps(record.get("affected_products", [])),
                record.get("source"), record.get("source_url"), now,
                1 if record.get("kev_status") else 0,
                record.get("epss_score"), record.get("epss_percentile"),
                record.get("remediation"), record.get("enriched_at"),
                primary_cve
            ))
            vuln_id = existing["id"]
        else:
            new_count += 1
            cursor = conn.execute("""
                INSERT INTO vulnerabilities (
                    cve_id, title, description, severity, cvss_score,
                    affected_products, source, source_url, published_date,
                    first_seen, last_seen, kev_status, epss_score, epss_percentile,
                    remediation, enriched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                primary_cve, record.get("title"), record.get("description"),
                record.get("severity"), record.get("cvss_score"),
                json.dumps(record.get("affected_products", [])),
                record.get("source"), record.get("source_url"), record.get("published_date"),
                now, now,
                1 if record.get("kev_status") else 0,
                record.get("epss_score"), record.get("epss_percentile"),
                record.get("remediation"), record.get("enriched_at")
            ))
            vuln_id = cursor.lastrowid

        matches = record.get("affected_tech", [])
        if matches:
            conn.execute("DELETE FROM tech_matches WHERE vuln_id = ?", (vuln_id,))
            for m in matches:
                conn.execute(
                    "INSERT INTO tech_matches (vuln_id, category, product, relevance_score) VALUES (?, ?, ?, ?)",
                    (vuln_id, m.get("category", ""), m.get("product", ""), m.get("score", 0))
                )

    conn.commit()
    conn.close()
    return new_count, updated_count


def save_run_history(total_scraped, total_normalized, total_relevant, new_threats, resolved_threats, summary):
    conn = get_conn()
    conn.execute(
        "INSERT INTO run_history (run_at, total_scraped, total_normalized, total_relevant, new_threats, resolved_threats, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), total_scraped, total_normalized, total_relevant, new_threats, resolved_threats, json.dumps(summary))
    )
    conn.commit()
    conn.close()


def get_filtered_threats():
    conn = get_conn()
    rows = conn.execute("""
        SELECT v.*, GROUP_CONCAT(tm.category || ':' || tm.product) as tech_matches
        FROM vulnerabilities v
        LEFT JOIN tech_matches tm ON v.id = tm.vuln_id
        WHERE v.id IN (SELECT DISTINCT vuln_id FROM tech_matches)
        GROUP BY v.id
        ORDER BY
            CASE v.severity
                WHEN 'Critical' THEN 0
                WHEN 'High' THEN 1
                WHEN 'Medium' THEN 2
                WHEN 'Low' THEN 3
                ELSE 4
            END,
            COALESCE(v.cvss_score, 0) DESC
    """).fetchall()
    conn.close()

    results = []
    for row in rows:
        record = dict(row)
        record["affected_products"] = json.loads(record.get("affected_products") or "[]")
        record["cwe_ids"] = json.loads(record.get("cwe_ids") or "[]")
        record["tags"] = json.loads(record.get("tags") or "[]")
        record["kev_status"] = bool(record.get("kev_status"))

        matches = []
        if record.get("tech_matches"):
            for pair in record["tech_matches"].split(","):
                if ":" in pair:
                    cat, prod = pair.split(":", 1)
                    matches.append({"category": cat, "product": prod})
        record["affected_tech"] = matches
        del record["tech_matches"]

        results.append(record)

    return results


def get_summary():
    conn = get_conn()
    relevant = conn.execute("""
        SELECT v.* FROM vulnerabilities v
        WHERE v.id IN (SELECT DISTINCT vuln_id FROM tech_matches)
    """).fetchall()
    conn.close()

    severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    kev_count = 0
    products = set()
    sources = set()

    for row in relevant:
        sev = row["severity"] or ""
        if sev in severity:
            severity[sev] += 1
        if row["kev_status"]:
            kev_count += 1
        products.update(json.loads(row["affected_products"] or "[]"))
        sources.add(row["source"] or "")

    return {
        "total_threats": len(relevant),
        "severity_breakdown": severity,
        "kev_count": kev_count,
        "products_affected": list(products),
        "sources": list(sources),
        "generated_at": datetime.utcnow().isoformat()
    }


def get_recent_runs(limit=10):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM scraper_runs ORDER BY run_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_threats_since(hours=24):
    conn = get_conn()
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        "SELECT * FROM vulnerabilities WHERE first_seen >= ? ORDER BY cvss_score DESC",
        (cutoff,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM vulnerabilities").fetchone()["c"]
    relevant = conn.execute("SELECT COUNT(*) as c FROM vulnerabilities WHERE id IN (SELECT DISTINCT vuln_id FROM tech_matches)").fetchone()["c"]
    runs = conn.execute("SELECT COUNT(*) as c FROM scraper_runs").fetchone()["c"]
    conn.close()
    return {"total_vulns": total, "relevant_vulns": relevant, "total_runs": runs}


init_db()
