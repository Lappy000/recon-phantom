# 🔍 Recon Phantom

[![CI](https://github.com/Lappy000/recon-phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/Lappy000/recon-phantom/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Async multi-engine reconnaissance & vulnerability scanner** with real-time WebSocket dashboard, modular scanner architecture, and comprehensive reporting.

## Features

- 🚀 **Fully async** — built on asyncio + httpx for maximum throughput
- 🔌 **Modular scanners** — port scan, subdomain enum, tech fingerprint, CVE lookup, directory brute, SSL analysis, DNS recon, WAF detection, JS analysis, git exposure
- 📡 **Real-time updates** — WebSocket-powered live scan progress
- 🌐 **REST API** — FastAPI backend for programmatic access
- 📊 **Rich CLI** — beautiful terminal output with progress bars and tables
- 📝 **Reports** — JSON, HTML (dark theme), PDF export
- 🗄️ **Scan history** — SQLite/PostgreSQL persistence
- 🕵️ **Stealth mode** — rate limiting, UA rotation, proxy support, jitter
- 🐳 **Docker ready** — single-command deployment

## Quick Start

```bash
# Install
pip install -e .

# Scan a target
recon-phantom scan example.com --modules all

# Start web UI
recon-phantom serve --port 8080

# Generate report
recon-phantom report --format html --output report.html
```

## Architecture

```
┌─────────────────────────────────────────────┐
│                   CLI / API                   │
├─────────────────────────────────────────────┤
│              Scan Engine (async)              │
│  ┌─────────┬──────────┬──────────┬────────┐ │
│  │  Task   │  Event   │  Rate    │Stealth │ │
│  │  Queue  │   Bus    │ Limiter  │ Layer  │ │
│  └─────────┴──────────┴──────────┴────────┘ │
├─────────────────────────────────────────────┤
│              Scanner Modules                  │
│  ┌──────┬──────┬──────┬──────┬──────┬─────┐ │
│  │ Port │ Sub  │ Tech │ CVE  │ Dir  │ SSL │ │
│  │ Scan │domain│  FP  │Lookup│Brute │ Chk │ │
│  └──────┴──────┴──────┴──────┴──────┴─────┘ │
├─────────────────────────────────────────────┤
│           Storage / Reporters                 │
│  ┌──────────┬──────┬──────┬──────┐          │
│  │ SQLite/  │ JSON │ HTML │ PDF  │          │
│  │ Postgres │      │      │      │          │
│  └──────────┴──────┴──────┴──────┘          │
└─────────────────────────────────────────────┘
```

## Scanner Modules

| Module | Description | Techniques |
|--------|-------------|------------|
| `port_scanner` | TCP/UDP port discovery | SYN probe, banner grab, service ID |
| `subdomain` | Subdomain enumeration | DNS brute, CT logs, web archives |
| `tech_fingerprint` | Technology detection | Headers, cookies, DOM patterns |
| `cve_lookup` | Vulnerability matching | NVD API, CPE correlation |
| `directory_bruteforce` | Path discovery | Async HTTP, status filtering |
| `ssl_analyzer` | TLS/SSL audit | Cert chain, ciphers, vulns |
| `dns_recon` | DNS intelligence | Zone xfer, record enum, cache snoop |
| `header_analyzer` | HTTP security headers | CSP, HSTS, CORS, X-headers |
| `waf_detector` | WAF fingerprinting | Response patterns, timing |
| `git_exposure` | Git repo leak detection | .git/HEAD, object dump |
| `js_analyzer` | JS secret extraction | Regex patterns, endpoint discovery |
| `nuclei_integration` | Nuclei template runner | Custom + community templates |

## Configuration

```yaml
# config.yaml
engine:
  max_concurrent_scans: 5
  max_tasks_per_scan: 100
  default_timeout: 30

stealth:
  enabled: true
  min_delay: 0.5
  max_delay: 2.0
  rotate_user_agents: true
  proxy_list: proxies.txt

reporting:
  auto_save: true
  output_dir: ./reports
  default_format: html
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/scans` | Create new scan |
| GET | `/api/v1/scans` | List all scans |
| GET | `/api/v1/scans/{id}` | Get scan details |
| DELETE | `/api/v1/scans/{id}` | Cancel/delete scan |
| GET | `/api/v1/scans/{id}/report` | Download report |
| WS | `/ws/scans/{id}` | Real-time updates |

## License

MIT
