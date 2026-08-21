# ThreatPulse

**Multi-source threat intelligence aggregator filtered by your company's tech stack.**

Built for the [Into the Scrape-Verse](https://wemakedevs.org/hackathons/scrape-verse) hackathon (WeMakeDevs x Bright Data, August 17–23, 2026).

## What it does

Scrapes vulnerability data from multiple security sources using Bright Data Scraper Studio, enriches with NVD/CISA KEV/EPSS APIs, and filters results to show **only the threats that affect your infrastructure**.

```
Scrape (Bright Data)  →  Normalize  →  Filter (your stack)  →  Enrich (NVD/KEV/EPSS)  →  Dashboard
```

### Key features

- **Tech stack filtering** — define what you run, see only relevant threats
- **Self-healing scrapers** — `bdata scraper heal` recovers from site layout changes
- **Multi-source aggregation** — THN, Fortinet PSIRT, web search in parallel
- **Enrichment layer** — CVSS scores, CISA KEV status, EPSS exploitation probability
- **Smart pipeline** — filters first (free), enriches only relevant records (saves API calls)

## Quick start

### Demo mode (no Bright Data needed)

```bash
cd threatpulse
pip install -r requirements.txt
python main.py --demo
```

Open `http://localhost:5000`

### Live mode (requires Bright Data CLI)

```bash
# Install and authenticate
npm install -g @anthropic/brightdata-cli
bdata auth login
bdata scraper promo wemakedevs    # $50 bonus credits

# Create scrapers (one-time, ~5 min)
bdata scraper create "https://thehackernews.com/search/label/Vulnerability" \
  "Extract all vulnerability articles: title, URL, date, tags, snippet. Also extract CVE IDs, CVSS scores, and affected products." \
  --name "ThreatPulse THN Vulns" --pretty

bdata scraper create "https://fortiguard.com/psirt" \
  "Extract all Fortinet security advisories: title, FG-IR ID, severity, date, products, description, link. Also extract CVE IDs." \
  --name "ThreatPulse Fortinet PSIRT" --pretty

bdata scraper create "https://www.google.com/search?q=critical+CVE+exploited+2026" \
  "Extract search results: title, URL, snippet, domain. Extract CVE IDs, CVSS scores, severity, and affected products." \
  --name "ThreatPulse Web Vuln Search" --pretty

# Save collector IDs to config/scrapers.json, then:
python main.py
```

Open `http://localhost:5000`

## Project structure

```
threatpulse/
├── main.py                          # Entry point
├── requirements.txt                 # Python dependencies
├── config/
│   ├── techstack.json               # Your company's tech stack (edit this)
│   └── scrapers.json                # Scraper configs + collector IDs
├── scrapers/
│   ├── setup_scrapers.py            # Create/run/heal Bright Data scrapers
│   └── demo_healing.py              # Self-healing demo script
├── pipeline/
│   ├── normalize.py                 # Raw scraper output → unified schema
│   ├── enrich.py                    # NVD + CISA KEV + EPSS enrichment
│   ├── filter.py                    # Tech stack matching engine
│   ├── database.py                  # SQLite layer (dedup, staleness, CRUD)
│   └── run_pipeline.py              # Chains: normalize → filter → enrich
├── dashboard/
│   ├── app.py                       # Flask web server
│   └── templates/dashboard.html     # Dark-themed threat dashboard
└── data/
    ├── demo/                        # Demo mode data
    ├── scraper/                     # Live scraper output
    └── threatpulse.db               # SQLite database
```

## How the pipeline works

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Scrape (Bright Data, threads, parallel)                │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ THN Vulns    │ │ Fortinet     │ │ Web Search   │             │
│  │ (Discovery)  │ │ (Sitemap)    │ │ (Search)     │             │
│  │ c_mt1qq...   │ │ c_mt1qt...   │ │ c_mt1r1...   │             │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘             │
│         └────────────────┼────────────────┘                     │
│                          ↓                                      │
│  STEP 2: Normalize (unified schema, deduplicate by CVE ID)      │
│                          ↓                                      │
│  STEP 3: Filter by tech stack (FREE, instant)                   │
│    341 records → 23 relevant (318 discarded, zero cost)         │
│                          ↓                                      │
│  STEP 4: Enrich only relevant records                           │
│    NVD API → CVSS vectors, CWE IDs (with retry on 429)          │
│    CISA KEV → actively exploited status                         │
│    EPSS → probability of exploitation                           │
│                          ↓                                      │
│  STEP 5: Save to SQLite + Dashboard (Flask, dark theme)         │
│    Shows: severity, CVSS, KEV badge, EPSS%, affected products  │
└─────────────────────────────────────────────────────────────────┘
```

## Database schema

SQLite at `data/threatpulse.db`, 4 tables:

```
scraper_runs
├── scraper_id        TEXT
├── collector_id      TEXT
├── run_at            TEXT
├── status            TEXT (success/failed)
├── records_count     INTEGER
└── raw_data          TEXT (JSON)

vulnerabilities (deduplicated by cve_id)
├── cve_id            TEXT UNIQUE
├── title, description, severity, cvss_score, cvss_vector
├── affected_products TEXT (JSON array)
├── source, source_url, published_date
├── first_seen, last_seen   (tracking freshness)
├── kev_status        INTEGER (0/1)
├── epss_score, epss_percentile
├── cwe_ids           TEXT (JSON array)
├── remediation, tags TEXT
└── enriched_at       TEXT

tech_matches (links vulns to your stack)
├── vuln_id           FK → vulnerabilities.id
├── category          TEXT
├── product           TEXT
└── relevance_score   INTEGER

run_history (pipeline run audit log)
├── run_at            TEXT
├── total_scraped, total_normalized, total_relevant
├── new_threats, resolved_threats
└── summary           TEXT (JSON)
```

Indexes on `cve_id`, `severity`, `last_seen`, `kev_status`, `vuln_id`, `run_at`.

## Tech stack config

Edit `config/techstack.json` to match your infrastructure:

```json
{
  "company": "Acme Corp",
  "operating_systems": ["Windows Server 2022", "Ubuntu 22.04"],
  "network_equipment": ["Fortinet FortiGate", "Cisco Catalyst"],
  "cloud": ["AWS", "Azure"],
  "virtualization": ["VMware vCenter", "VMware ESXi"],
  "software": ["Microsoft SharePoint", "GitLab", "Docker", "Kubernetes"],
  "languages": ["Python", "Node.js", "Java"],
  "browsers": ["Chrome", "Edge"]
}
```

The filter matches threats against every entry in this config. Only threats affecting your stack appear on the dashboard.

## Dashboard

Opens at `http://localhost:5000` after running `python main.py`.

## Self-healing demo

Shows how Bright Data recovers when a site changes its layout:

```bash
python scrapers/demo_healing.py c_mt1qqsek22fynhmqyp
```

```
Phase 1: Run scraper (works)
Phase 2: Site layout changes (simulated)
Phase 3: Run scraper (breaks)
Phase 4: bdata scraper heal (AI re-analyzes page)
Phase 5: Run scraper (recovers, same collector_id)
```

## Credit usage

| Step | Cost |
|---|---|
| 3 scraper runs (parallel via threads) | ~9 Bright Data credits |
| CISA KEV API | Free |
| EPSS API | Free |
| NVD API | Free (rate limited, with retry) |
| **Total per run** | **~9 credits** |

Pipeline filters first (free), then enriches only relevant records — saving ~75% of API calls compared to enriching everything.

## Commands

```bash
# Full pipeline (scrape + enrich + filter + dashboard)
python main.py

# Demo mode (sample data)
python main.py --demo

# Dashboard only
python main.py --serve-only

# Create scrapers
python scrapers/setup_scrapers.py --create

# Run scrapers only
python scrapers/setup_scrapers.py --run

# Heal a scraper
python scrapers/setup_scrapers.py --heal <collector_id>

# List scrapers
python scrapers/setup_scrapers.py --list

# Run pipeline independently
python pipeline/run_pipeline.py data/scraper
python pipeline/run_pipeline.py data/demo
```

## Dependencies

```
flask>=3.0
requests>=2.31
python-dateutil>=2.9
rich>=14.0
```

Plus the Bright Data CLI (`npm install -g @anthropic/brightdata-cli`).

## License

MIT
