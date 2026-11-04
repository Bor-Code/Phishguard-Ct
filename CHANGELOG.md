# Changelog

All notable changes to **PhishGuard-CT** are documented in this file.

## [1.0.0] - 2026-11-04

### Added
- **Certstream Ingestion (`phishguard.ingestion`)**: Real-time WebSocket streaming client with exponential backoff, wildcard stripping, and Punycode normalization.
- **Multi-Signal Scoring Engine (`phishguard.scoring`)**: Weighted similarity scoring combining Levenshtein edit distance, QWERTY keyboard adjacency, homoglyph/IDN normalization, and subdomain/affix combo-squatting detection.
- **Brand Watchlist & Alias Resolution (`phishguard.watchlist`)**: Protected brand registry with canonical domain whitelisting and secondary brand keyword/alias resolution (`facebook`/`instagram` -> `meta`, `outlook`/`office365` -> `microsoft`, `icloud` -> `apple`, `steampowered` -> `steam`).
- **Active Verification Layer (`phishguard.verification`)**: Asynchronous HTTP/HTTPS reachability probing, TLS certificate issuance age & free automated CA analysis, HTML credential-harvesting heuristics (`<input type="password">`, login forms), and structural TLD/hyphen risk heuristics.
- **SQLite Storage & Migrations (`phishguard.storage`)**: WAL-mode SQLite persistence, schema migrations, summary telemetry queries, and CSV/JSON export.
- **Multi-Channel Alerting (`phishguard.alerting`)**: Webhook dispatcher supporting Discord Rich Embeds, Slack Block Kit, Telegram Bot HTML messages, and generic SIEM JSON payloads.
- **Benchmark Evaluation Pipeline (`phishguard.evaluation`)**: Automated evaluation against PhishTank, OpenPhish, and Benign sample datasets achieving `1.0000` Precision, `1.0000` Recall, and `1.0000` F1-Score.
- **REST API & SOC Web Dashboard (`phishguard.api`)**: Dark-mode SOC Threat Intelligence Web Console (`GET /`, `/dashboard`) and JSON REST endpoints (`/health`, `/stats`, `/domains`, `/domains/{domain}`, `POST /scan`).
- **Unified CLI (`phishguard.cli`)**: `monitor`, `scan`, `batch`, `export`, `serve`, `evaluate`, and `list` commands.
- **Docker Support**: `Dockerfile` and `docker-compose.yml` for containerized deployment.
