# SOC-GPT 2.0

[![CI](https://github.com/0mer-byte/soc-gpt/actions/workflows/test.yml/badge.svg)](https://github.com/0mer-byte/soc-gpt/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)]()
[![Verdict Accuracy](https://img.shields.io/badge/verdict%20accuracy-6%2F6-success)]()

AI-powered SIEM alert triage platform. Multi-LLM consensus voting between a local Llama 3.2 model and Groq's cloud-hosted gpt-oss-120b, with a deterministic safety-rail override for known-dangerous alert categories. Runs entirely on commodity hardware — no cloud bills, no credit card required.

## What it does

A Tier-1 SOC analyst reviews 500–2,000 alerts per shift. 95%+ are false positives. SOC-GPT acts as an AI co-pilot: it receives alerts via webhook, triages each one through multiple LLMs in parallel, takes a majority vote, applies a deterministic safety guard on critical keywords (malware, ransomware, privilege escalation), and routes the result to auto-close, human escalation, or auto-respond.

Current verdict accuracy on the built-in sample alert suite: **6 of 6 correct**, zero catastrophic misclassifications.

## Architecture

```
Wazuh / SIEM
    │
    ▼  (HTTP POST /webhook/alert)
FastAPI Server (uvicorn, port 8000)
    │
    ▼
Consensus Engine  ──►  [ Ollama · local Llama 3.2 3B ]  ──►  vote
                  ──►  [ Groq · gpt-oss-120b (cloud) ]  ──►  vote
    │                                         │
    │  majority wins, conservative on ties    │
    ▼                                         ▼
Decision Router
    ├── Critical Keyword Guard ──► ESCALATE (safety-rail override)
    ├── Malicious + high conf ───► AUTO-BLOCK (simulated)
    ├── Malicious or escalate ───► ESCALATE (simulated Slack)
    └── Benign / low conf ───────► AUTO-CLOSE
    │
    ▼
SQLite Decision Log + Live HTML Dashboard
```

## Quick start

### Prereqs

- Python 3.11+
- [Ollama](https://ollama.com) installed and running locally
- Llama 3.2 3B model: `ollama pull llama3.2:3b`
- A free [Groq](https://console.groq.com) account for the second LLM (no credit card)

### Install

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### Run

```bash
py -m uvicorn src.api.server:app --reload --host 0.0.0.0 --port 8000
```

### Fire test alerts

```bash
py scripts/batch_triage.py
```

Open the dashboard: **http://localhost:8000/dashboard**

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Service status + active engine |
| GET | `/health` | Health check |
| POST | `/webhook/alert` | Submit alert for triage |
| GET | `/decisions?limit=N` | Recent triage history |
| GET | `/stats` | Aggregate statistics |
| GET | `/dashboard` | Live HTML dashboard |
| GET | `/docs` | Swagger API documentation |

## Defense in depth: why the safety rail exists

During testing, Llama 3.2 3B classified an active Trojan.CryptoLocker alert as **benign** with 80% confidence. That's a catastrophic miss — the ransomware alert would have been silently auto-closed in production.

Two defenses now prevent this:

1. **Multi-LLM consensus** — Groq's larger `gpt-oss-120b` correctly flagged the alert as malicious at 96% confidence, and the consensus vote overrode the smaller model.

2. **Critical keyword guard** — Even if both LLMs got it wrong, rules containing terms like `malware`, `trojan`, `ransomware`, `exploit`, `privilege escalation`, or `data exfiltration` can never be auto-closed. The verdict is forced to ESCALATE.

AI makes the nuanced calls. Deterministic rules catch the catastrophic misses. Both must agree before anything gets closed.

## Project layout

```
soc-gpt/
├── .github/
│   ├── workflows/test.yml          # CI
│   ├── ISSUE_TEMPLATE/             # Bug + feature templates
│   └── pull_request_template.md
├── src/
│   ├── api/server.py               # FastAPI app + dashboard
│   ├── core/
│   │   ├── alert.py                # Alert data model
│   │   ├── consensus.py            # Multi-LLM voting engine
│   │   ├── response.py             # Decision router + safety rail
│   │   └── storage.py              # SQLite decision log
│   └── llm/
│       ├── base.py                 # LLMProvider abstract interface
│       ├── ollama_provider.py      # Local Ollama (Llama 3.2 3B)
│       └── groq_provider.py        # Groq cloud (gpt-oss-120b)
├── scripts/
│   ├── triage_alert.py             # Single alert end-to-end test
│   ├── test_groq.py                # Groq connectivity test
│   └── batch_triage.py             # Batch runner for sample suite
├── examples/                       # 6 diverse sample alerts
├── config/                         # Example configuration
├── docs/roadmap.md                 # 6-week build plan
└── tests/                          # pytest suite
```

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md).

- ✅ **Week 1** — Local LLM, webhook server, SQLite, safety rails, dashboard
- ✅ **Week 2** — Multi-LLM consensus, Groq integration *(shipped early)*
- ⬜ **Week 3** — Enrichment layer (IP reputation, VirusTotal, GeoIP)
- ⬜ **Week 4** — Real auto-response (UFW, Wazuh Active Response)
- ⬜ **Week 5** — Advanced analytics and alert deduplication
- ⬜ **Week 6** — Real Wazuh integration on DigitalOcean + demo video

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: see [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).

## Author

**Omar Malik Asghar** · Senior at Rock Ridge HS, Ashburn VA · CompTIA Security+ (Dec 2026) · CyberPatriot State Round qualifier

Open to data center / SOC internship conversations in Northern Virginia for summer 2027.