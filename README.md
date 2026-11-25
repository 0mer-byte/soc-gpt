# SOC-GPT 2.0

AI-powered SIEM alert triage platform. Runs entirely on local hardware — no cloud bills, no API fees, no credit card. Combines a local LLM (Llama 3.2) with deterministic safety rails so dangerous alerts can never be silently auto-closed.

![Status](https://img.shields.io/badge/status-Week%201%20complete-brightgreen)
![Stack](https://img.shields.io/badge/stack-Python%20%7C%20FastAPI%20%7C%20Ollama%20%7C%20SQLite-blue)

## What it does

A Tier-1 SOC analyst reviews 500–2,000 alerts per shift. 95%+ are false positives. SOC-GPT acts as an AI co-pilot: it receives alerts via webhook, enriches them, runs them through an LLM for triage, and either auto-closes, escalates to a human, or auto-responds (blocks the source).

## Architecture

```
Wazuh / SIEM
    │
    ▼  (HTTP POST webhook)
FastAPI Server (uvicorn, port 8000)
    │
    ▼
Local LLM (Ollama + Llama 3.2 3B)
    │
    ▼
Decision Router
    │
    ├── Critical Keyword Guard ──► ESCALATE (override)
    ├── Malicious + high conf ───► AUTO-BLOCK (simulated)
    ├── Suspicious / malicious ──► ESCALATE (simulated Slack)
    └── Benign / low conf ───────► AUTO-CLOSE
    │
    ▼
SQLite Decision Log + Live Dashboard
```

## Running it locally

### Prereqs
- Python 3.12+
- [Ollama](https://ollama.com) installed and running
- `llama3.2:3b` model pulled: `ollama pull llama3.2:3b`

### Setup
```bash
pip install -r requirements.txt
```

### Run the server
```bash
py -m uvicorn src.api.server:app --reload --host 0.0.0.0 --port 8000
```

### Endpoints
- `GET  /` — service status
- `GET  /health` — health check
- `POST /webhook/alert` — submit an alert for triage
- `GET  /decisions` — recent triage decisions
- `GET  /stats` — aggregate statistics
- `GET  /dashboard` — live HTML dashboard
- `GET  /docs` — Swagger API docs

### Test it
```bash
# Fire 6 sample alerts (benign + suspicious + malicious)
py scripts/batch_triage.py

# Open the dashboard
start http://localhost:8000/dashboard
```

## Safety: defense in depth

LLMs are not perfect. A 3B-parameter model will occasionally classify a real threat as benign — in testing, Llama 3.2 flagged an active Trojan.CryptoLocker detection as `benign` with 80% confidence.

To prevent AI misclassification from causing a security incident, SOC-GPT enforces a **critical keyword guard** in `src/core/response.py`. Rules containing terms like `malware`, `trojan`, `ransomware`, `exploit`, `privilege escalation`, or `data exfiltration` can NEVER be auto-closed — the LLM's verdict is overridden in favor of human escalation. The LLM retains judgment, but a deterministic safety layer catches the catastrophic misses.

## Project layout

```
soc-gpt/
├── src/
│   ├── api/          # FastAPI server + HTML dashboard
│   ├── core/         # Alert model, SQLite storage, decision router
│   └── llm/          # Pluggable LLM providers (Ollama, later: Claude, GPT-4)
├── scripts/          # Batch triage runner, test scripts
├── examples/         # 6 diverse sample alerts
├── config/           # Example configuration
├── docs/             # Roadmap, architecture notes
└── tests/            # Unit tests (coming in Week 2)
```

## Status — Week 1 of 6 complete

See `docs/roadmap.md` for the full plan.

## Author

Omar Malik Asghar · Senior at Rock Ridge HS, Ashburn VA · CompTIA Security+ (Dec 2026) · CyberPatriot State Round qualifier