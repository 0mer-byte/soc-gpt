# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-25

### Added
- Multi-LLM consensus voting engine (`src/core/consensus.py`)
- Groq cloud provider integration (`src/llm/groq_provider.py`) using `openai/gpt-oss-120b`
- Parallel LLM execution for sub-2-minute batch triage of 6 alerts
- Agreement classification (UNANIMOUS / MAJORITY / SPLIT) surfaced on dashboard
- Dashboard engine identifier showing active provider stack
- Unit tests for consensus engine, decision router, and safety rails
- GitHub Actions CI with Python 3.11 and 3.12 matrix

### Changed
- `/webhook/alert` now routes through consensus engine instead of single Ollama provider
- Dashboard verdict rows show per-decision agreement tags
- Verdict accuracy improved from 2/6 correct to 6/6 correct on sample alert suite

### Security
- Added `.env` to `.gitignore` to prevent API key leakage

## [0.1.0] - 2026-11-24

### Added
- FastAPI webhook server with `/webhook/alert` endpoint
- Local Ollama LLM provider (Llama 3.2 3B)
- SQLite persistent decision log
- Decision router with auto-block / escalate / auto-close routing
- Critical keyword safety rail (malware, trojan, ransomware, etc.)
- 6 diverse sample alerts covering the full SOC spectrum
- Live HTML dashboard with metrics, charts, and decision table
- Batch triage runner script
- Initial project scaffolding, README, and 6-week roadmap