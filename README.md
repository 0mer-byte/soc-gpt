# SOC-GPT 2.0

AI-powered SIEM alert triage platform. Reduces SOC analyst alert fatigue by using multi-LLM analysis to classify, prioritize, and auto-respond to security events.

## Why

A Tier-1 SOC analyst reviews 500–2,000 alerts per shift. 95%+ are false positives. SOC-GPT acts as an AI co-pilot: it reads the raw Wazuh alert, enriches it with threat intel, consults 2–3 LLMs for consensus, and either auto-closes the alert with reasoning or escalates to a human with a complete writeup.

## Architecture

Wazuh SIEM → Alert Webhook → SOC-GPT Core → Multi-LLM Voting → Decision

The decision routes one of three ways: auto-close, escalate to human, or auto-respond (e.g. block IP, lock account).

## Stack

- **SIEM**: Wazuh 4.x (self-hosted on Ubuntu 22.04)
- **AI**: Claude Sonnet, OpenAI GPT-4, local Ollama (Llama 3.1 8B)
- **Backend**: Python 3.12 · FastAPI · SQLite
- **Frontend**: Streamlit dashboard
- **Deploy**: DigitalOcean Droplet

## Status

**In active development** — Week 1 of 6-week build plan. See `docs/roadmap.md`.

## Author

Omar Malik Asghar · Senior at Rock Ridge HS, Ashburn VA · CompTIA Security+ · CyberPatriot 