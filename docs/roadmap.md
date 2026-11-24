# SOC-GPT 2.0 — 6 Week Build Roadmap

## Week 1 — Foundation (current)
- [x] Project scaffolding + repo
- [ ] Local LLM (Ollama + Llama 3.2) running on dev machine
- [ ] First working alert-triage code
- [ ] Wazuh VPS provisioning (pending DigitalOcean credit)
- [ ] First real alerts from Wazuh webhook

## Week 2 — Multi-LLM Voting
- [ ] Claude provider implementation
- [ ] OpenAI provider implementation
- [ ] Consensus algorithm (majority vote across 3 LLMs)
- [ ] Confidence scoring

## Week 3 — Decision Engine
- [ ] Auto-close / escalate / respond routing
- [ ] SQLite decision log
- [ ] Alert deduplication

## Week 4 — Auto-Response
- [ ] IP blocking via UFW on Wazuh agents
- [ ] Account lockout via Wazuh Active Response
- [ ] Email + Slack escalation for high-severity

## Week 5 — Dashboard
- [ ] Streamlit UI
- [ ] Live alert feed
- [ ] Decision history + manual override
- [ ] Analytics (false positive rate, LLM agreement %)

## Week 6 — Demo & Deploy
- [ ] Attack simulation (Atomic Red Team)
- [ ] 3-minute demo video
- [ ] Case study writeup for portfolio
- [ ] LinkedIn + resume update