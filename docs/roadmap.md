# SOC-GPT 2.0 — 6 Week Build Roadmap

## Week 1 — Foundation ✅ COMPLETE
- [x] Project scaffolding + repo
- [x] Local LLM (Ollama + Llama 3.2) running on dev machine
- [x] First working alert-triage code
- [x] FastAPI webhook server
- [x] SQLite decision log
- [x] Decision router with critical keyword safety guard
- [x] 6 diverse sample alerts + batch runner
- [x] Live HTML dashboard with charts and metrics
- [ ] Wazuh VPS provisioning (pending DigitalOcean credit)
- [ ] First real alerts from Wazuh webhook

## Week 2 — Multi-LLM Voting ✅ COMPLETE (shipped Nov 25, Day 2)
- [x] Groq provider (gpt-oss-120b, free tier, no credit card)
- [x] Consensus engine with parallel LLM execution
- [x] Majority vote with conservative tie-breaking
- [x] Per-LLM agreement tags (UNANIMOUS / MAJORITY / SPLIT) on dashboard
- [x] Accuracy improved from 2/6 to 6/6 correct verdicts

## Week 3 — Enrichment Layer ✅ COMPLETE (shipped Nov 27, Day 4)
- [x] AbuseIPDB integration (free tier, 1,000 checks/day)
- [x] IP reputation feeds LLM prompt before triage
- [x] Private IP skip logic (RFC 1918 ranges)
- [x] Fail-safe design — API errors don't block triage
- [ ] Future: VirusTotal for file hashes, GeoIP enrichment, MISP integration

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

