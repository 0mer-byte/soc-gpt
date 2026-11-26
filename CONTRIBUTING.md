# Contributing to SOC-GPT

Thanks for your interest in improving SOC-GPT. This document explains how to set up a development environment and the standards we follow for contributions.

## Setup

1. Fork the repo and clone your fork
2. Install Ollama and pull Llama 3.2: `ollama pull llama3.2:3b`
3. Install Python dependencies: `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and add your `GROQ_API_KEY`
5. Run the test suite: `pytest tests/ -v`
6. Start the server: `py -m uvicorn src.api.server:app --reload`

## Development workflow

- Create a feature branch: `git checkout -b feature/short-description`
- Make your changes with clear, atomic commits
- Add tests for any new logic
- Ensure `pytest` passes before opening a PR
- Open a pull request against `main` with a clear description

## Code standards

- Python 3.11+ with type hints on public interfaces
- Keep functions under ~50 lines where practical
- Prefer composition over inheritance for new providers
- Any new LLM backend must implement the `LLMProvider` interface in `src/llm/base.py`
- Security-relevant changes must include a test case covering the failure mode

## Adding a new LLM provider

1. Create `src/llm/<name>_provider.py`
2. Subclass `LLMProvider` and implement `analyze_alert` + `name`
3. Add integration into `src/api/server.py` lifespan
4. Add unit tests using the `MockProvider` pattern in `tests/test_consensus.py`
5. Document the provider in the README

## Reporting bugs

Open an issue using the bug report template. For security vulnerabilities see `SECURITY.md`.