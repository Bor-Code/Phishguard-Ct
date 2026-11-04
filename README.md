<div align="center">

# PhishGuard-CT

**Real-Time Certificate Transparency Phishing Detection and SOC Triage Platform**

[![CI](https://github.com/Bor-Code/Phishguard-Ct/actions/workflows/ci.yml/badge.svg)](https://github.com/Bor-Code/Phishguard-Ct/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)](CHANGELOG.md)
[![F1-Score](https://img.shields.io/badge/F1--Score-100%25-brightgreen.svg)](reports/evaluation_report.json)

</div>

---

## 1. System Architecture

```mermaid
flowchart TD
    subgraph INGEST["1. Data Ingestion"]
        CT["CertStream WebSocket\n(Live SSL/TLS Stream)"]
        CLI_IN["CLI / Batch Input\n(Single & Bulk Scanning)"]
        API_IN["REST API & Web UI\n(On-Demand Analysis)"]
    end

    subgraph ENGINE["2. Detection & Scoring Engine"]
        NORM["Domain Normalizer\n(Punycode & Wildcard Stripping)"]
        WL["Brand Watchlist\n(10 Target Brands & Alias Resolver)"]
        SCORE["4-Signal Similarity Engine\n(Levenshtein + Keyboard + Homoglyph + Affix)"]
    end

    subgraph VERIFY["3. Active Verification"]
        DNS["DNS Resolver\n(A / AAAA IP Records)"]
        HTTP["HTTP / HTML Probe\n(Login & Password Form Detection)"]
        TLS["Certificate & TLD Heuristics\n(Free CA / Cert Age / Suspicious TLDs)"]
    end

    subgraph OUTPUT["4. Persistence, Alerting & SOC UI"]
        DB[("SQLite Database\n(WAL Mode)")]
        DASH["SOC Web Dashboard\n(Interactive Charts & Triage)"]
        WEBHOOK["Multi-Channel Alerting\n(Discord / Slack / Telegram)"]
    end

    CT & CLI_IN & API_IN --> NORM --> WL --> SCORE
    SCORE -->|"Score >= Threshold (0.75)"| DNS & HTTP & TLS
    DNS & HTTP & TLS --> DB
    DB --> DASH
    DB -->|"High Confidence"| WEBHOOK
```

---

## 2. Multi-Signal Scoring Pipeline

```mermaid
flowchart LR
    D["Candidate Domain:\npaypa1-secure.xyz"] --> S1 & S2 & S3 & S4

    S1["Levenshtein (35%)\nCharacter Edit Distance"]
    S2["Keyboard (25%)\nQWERTY Adjacency"]
    S3["Homoglyph (25%)\nVisual Lookalikes (l -> 1)"]
    S4["Affix / Token (15%)\nBrand + Deceptive Affixes"]

    S1 & S2 & S3 & S4 --> COMP["Composite Score\n(0.00 - 1.00)"]
    COMP --> MULT["Verification Multiplier\n(x1.00 - x1.50)"]
    MULT --> FINAL["Final Confidence Score"]
```

| Signal | Weight | Target Attack Vector | Example |
| :--- | :---: | :--- | :--- |
| **Levenshtein** | `35%` | Character insertions, deletions, substitutions | `paypaI.com`, `gooogle.com` |
| **Keyboard** | `25%` | Adjacent QWERTY key typosquatting | `payoal.com`, `gppgle.com` |
| **Homoglyph** | `25%` | Visual lookalikes (`0`/`o`, `1`/`l`, IDN Cyrillic) | `paypa1.com`, `faceb00k.com` |
| **Affix / Subdomain** | `15%` | Brand combo-squatting and deceptive tokens | `paypal-login-verify.xyz` |

---

## 3. Threat Triage Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Candidate: Certificate / URL Ingested
    Candidate --> Legitimate: Canonical Brand Domain (Allowlist)
    Candidate --> LowRisk: Score < 0.75
    Candidate --> flagged: Score >= 0.75 (Persisted to DB)
    flagged --> alert_sent: Webhook Notification Dispatched
    flagged --> confirmed: Analyst Confirmed Threat
    alert_sent --> confirmed: Analyst Confirmed Threat
    flagged --> dismissed: Analyst Dismissed False Positive
    alert_sent --> dismissed: Analyst Dismissed False Positive
```

---

## 4. SOC Web Console Layout

```text
+-----------------------------------------------------------------------------------+
| PhishGuard-CT SOC Console v1.0.0             [Export JSON] [Export CSV] [Refresh] |
+--------------------+--------------------------------------------------------------+
| > Overview & Charts|  [ Flagged: 24 ]  [ Live Threats: 18 ]  [ Brands: 10 ]       |
| > Threat Explorer  |                                                              |
| > Batch Scanner    |  +----------------------+  +------------------------------+  |
| > Brand Watchlist  |  |  (O) Status Donut    |  |  Critical >=0.90 [########]  |  |
|                    |  |      flagged / sent  |  |  High 0.75-0.89  [#####   ]  |  |
|                    |  +----------------------+  +------------------------------+  |
|                    |                                                              |
|                    |  Domain                        Brand    Score    Actions     |
|                    |  ----------------------------------------------------------  |
|                    |  paypa1-secure-verify.com      paypal   0.9850   [Inspect]   |
|                    |  g00gle-workspace-sso.xyz      google   0.9240   [Confirm]   |
+--------------------+--------------------------------------------------------------+
```

---

## 5. Quick Start

### Installation

```bash
git clone https://github.com/Bor-Code/Phishguard-Ct.git
cd Phishguard-Ct
python -m venv .venv
.\.venv\Scripts\activate   # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

### CLI Commands

| Operation | Command |
| :--- | :--- |
| **Start SOC Web Dashboard & API** | `phishguard serve --host 127.0.0.1 --port 8080` |
| **Stream Live CT Logs** | `phishguard monitor --min-score 0.75` |
| **Inspect Single Domain / URL** | `phishguard scan paypa1-login.xyz --json` |
| **Run Bulk File Scan** | `phishguard batch domains.txt --output results.json` |
| **Export Flagged Database** | `phishguard export threats.csv --format csv` |
| **Run Benchmark Evaluation** | `phishguard evaluate --output-dir reports` |

---

## 6. REST API Sequence & Reference

```mermaid
sequenceDiagram
    participant Analyst as SOC Analyst / Web UI
    participant API as PhishGuard API (:8080)
    participant DB as SQLite Database

    Analyst->>API: GET /stats
    API->>DB: Query summary metrics and distributions
    DB-->>API: KPI counts + chart buckets
    API-->>Analyst: 200 OK (JSON)

    Analyst->>API: POST /scan {"domain": "paypa1-secure.com", "save": true}
    API->>DB: Persist flagged suspect record
    API-->>Analyst: 200 OK (Confidence Score + Signals)

    Analyst->>API: PATCH /domains/paypa1-secure.com {"status": "confirmed"}
    API->>DB: Update status to 'confirmed'
    API-->>Analyst: 200 OK
```

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/` or `/dashboard` | Interactive SOC Web Dashboard |
| `GET` | `/health` | Service health status and version |
| `GET` | `/stats` | Summary metrics, severity buckets, and signal averages |
| `GET` | `/domains` | Filtered list of flagged domains (`?brand=`, `?status=`, `?min_score=`) |
| `GET` | `/domains/{domain}` | Full domain record, signals, and certificate telemetry |
| `PATCH` | `/domains/{domain}` | Update domain triage status (`confirmed` / `dismissed`) |
| `POST` | `/scan` | On-demand single domain/URL inspection |
| `POST` | `/batch-scan` | Concurrent bulk domain inspection |
| `GET` | `/watchlist` | Protected target brands, keywords, and canonical domains |
| `GET` | `/export` | Download detections as `JSON` or `CSV` (`?format=csv`) |

---

## 7. Benchmark Performance

| Metric | Result |
| :--- | :---: |
| **Total Samples** | `44` (`24` Phishing / `20` Benign) |
| **True Positives (TP) / False Positives (FP)** | `24` / `0` |
| **Precision** | **`100%` (`1.0000`)** |
| **Recall** | **`100%` (`1.0000`)** |
| **F1-Score** | **`100%` (`1.0000`)** |

---

## 8. Docker & Testing

```bash
# Run with Docker Compose
docker compose up -d --build

# Execute unit and integration test suite
pytest
```

---

## License

Released under the [MIT License](LICENSE).
