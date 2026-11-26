"""FastAPI webhook server — receives security alerts and triages them via multi-LLM consensus."""

import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from src.core.consensus import ConsensusEngine
from src.core.response import route_decision
from src.core.storage import DecisionStore
from src.llm.groq_provider import GroqProvider
from src.llm.ollama_provider import OllamaProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

engine: ConsensusEngine | None = None
store: DecisionStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, store
    providers = [OllamaProvider(), GroqProvider()]
    engine = ConsensusEngine(providers)
    store = DecisionStore()
    store.init_db()
    logger.info("SOC-GPT ready — %s", engine.name)
    yield
    logger.info("SOC-GPT shutting down")


app = FastAPI(
    title="SOC-GPT 2.0 API",
    description="AI-powered SIEM alert triage with multi-LLM consensus voting",
    version="0.2.0",
    lifespan=lifespan,
)


class AlertWebhook(BaseModel):
    alert_id: str
    timestamp: str
    rule_id: str
    rule_description: str
    severity: int = Field(..., ge=0, le=15)
    agent_name: str
    agent_ip: str
    source_ip: str | None = None
    user_attempted: str | None = None
    raw_log: str
    notes: str | None = None


@app.get("/")
async def root():
    return {
        "service": "SOC-GPT 2.0",
        "status": "operational",
        "engine": engine.name if engine else "not initialized",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/webhook/alert")
async def receive_alert(alert: AlertWebhook):
    logger.info("Received alert %s: %s", alert.alert_id, alert.rule_description)
    alert_dict = alert.model_dump()
    decision = await engine.analyze_alert(alert_dict)
    action = route_decision(decision, rule_description=alert.rule_description)
    store.log_decision(
        alert_id=alert.alert_id,
        agent=alert.agent_name,
        rule=alert.rule_description,
        verdict=decision.verdict,
        confidence=decision.confidence,
        reasoning=decision.reasoning,
        recommended=decision.recommended_action,
        action_taken=action,
        llm_name=engine.name,
    )
    return {
        "alert_id": alert.alert_id,
        "verdict": decision.verdict,
        "confidence": decision.confidence,
        "reasoning": decision.reasoning,
        "action_taken": action,
    }


@app.get("/decisions")
async def list_decisions(limit: int = 50):
    return {"decisions": store.get_recent(limit)}


@app.get("/stats")
async def stats():
    return store.get_stats()


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SOC-GPT 2.0 Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, 'Segoe UI', sans-serif; background: #0b1120; color: #e5e7eb; padding: 24px; min-height: 100vh; }
header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #1f2937; }
h1 { font-size: 22px; font-weight: 600; }
.subtitle { color: #9ca3af; font-size: 13px; margin-top: 4px; }
.status { font-size: 12px; color: #10b981; display: flex; align-items: center; gap: 6px; }
.status::before { content: ''; width: 8px; height: 8px; border-radius: 50%; background: #10b981; animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.metric { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; }
.metric-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px; }
.metric-value { font-size: 32px; font-weight: 700; }
.metric-sub { font-size: 12px; color: #6b7280; margin-top: 4px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
.card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; }
.card h2 { font-size: 14px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 10px 12px; background: #0b1120; color: #9ca3af; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; border-bottom: 1px solid #1f2937; }
td { padding: 12px; border-bottom: 1px solid #1f2937; vertical-align: top; }
tr:hover td { background: #0f1729; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
.badge-malicious { background: #7f1d1d; color: #fecaca; }
.badge-suspicious { background: #78350f; color: #fde68a; }
.badge-benign { background: #064e3b; color: #a7f3d0; }
.agreement { font-size: 10px; color: #6b7280; margin-top: 2px; }
.agreement.unanimous { color: #10b981; }
.agreement.split { color: #f59e0b; }
.action { font-size: 12px; color: #9ca3af; }
.action.override { color: #f59e0b; font-weight: 600; }
.engine-info { background: #0f1729; border: 1px solid #1f2937; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 13px; color: #9ca3af; }
.engine-info strong { color: #e5e7eb; }
canvas { max-height: 260px; }
footer { text-align: center; color: #6b7280; font-size: 12px; margin-top: 24px; }
</style>
</head>
<body>
<header>
    <div>
        <h1>&#128737; SOC-GPT 2.0 &mdash; Alert Triage Dashboard</h1>
        <div class="subtitle">Multi-LLM consensus triage &middot; local Ollama + Groq cloud</div>
    </div>
    <div class="status">LIVE</div>
</header>
<div class="engine-info">
    <strong>Triage engine:</strong> <span id="engineName">loading...</span>
</div>
<div class="metrics" id="metrics"></div>
<div class="grid">
    <div class="card">
        <h2>Verdict Distribution</h2>
        <canvas id="verdictChart"></canvas>
    </div>
    <div class="card">
        <h2>Action Distribution</h2>
        <canvas id="actionChart"></canvas>
    </div>
</div>
<div class="card">
    <h2>Recent Decisions</h2>
    <table>
        <thead><tr><th>Time</th><th>Agent</th><th>Rule</th><th>Verdict</th><th>Conf</th><th>Action</th></tr></thead>
        <tbody id="decisionsBody"></tbody>
    </table>
</div>
<footer>Auto-refreshes every 10 seconds &middot; <span id="lastUpdate"></span></footer>
<script>
let verdictChart, actionChart;
async function fetchData() {
    const [root, stats, decisions] = await Promise.all([
        fetch('/').then(r => r.json()),
        fetch('/stats').then(r => r.json()),
        fetch('/decisions?limit=50').then(r => r.json()),
    ]);
    document.getElementById('engineName').textContent = root.engine || 'unknown';
    renderMetrics(stats);
    renderVerdictChart(stats.by_verdict);
    renderActionChart(stats.by_action);
    renderTable(decisions.decisions);
    document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
}
function renderMetrics(stats) {
    const total = stats.total_alerts || 0;
    const blocked = countMatching(stats.by_action, 'AUTO-BLOCK');
    const escalated = countMatching(stats.by_action, 'ESCALATE');
    const closed = countMatching(stats.by_action, 'AUTO-CLOSE');
    const avgConf = ((stats.average_confidence || 0) * 100).toFixed(0);
    document.getElementById('metrics').innerHTML = `
        <div class="metric"><div class="metric-label">Total Alerts</div><div class="metric-value">${total}</div></div>
        <div class="metric"><div class="metric-label">Auto-Blocked</div><div class="metric-value" style="color:#ef4444">${blocked}</div><div class="metric-sub">${pct(blocked, total)}</div></div>
        <div class="metric"><div class="metric-label">Escalated</div><div class="metric-value" style="color:#f59e0b">${escalated}</div><div class="metric-sub">${pct(escalated, total)}</div></div>
        <div class="metric"><div class="metric-label">Auto-Closed</div><div class="metric-value" style="color:#10b981">${closed}</div><div class="metric-sub">${pct(closed, total)}</div></div>
        <div class="metric"><div class="metric-label">Avg Confidence</div><div class="metric-value">${avgConf}%</div></div>
    `;
}
function countMatching(dict, substr) { let total = 0; for (const [k, v] of Object.entries(dict || {})) if (k.includes(substr)) total += v; return total; }
function pct(num, total) { return !total ? '0%' : Math.round(num / total * 100) + '% of total'; }
function renderVerdictChart(byVerdict) {
    const labels = Object.keys(byVerdict || {});
    const data = labels.map(l => byVerdict[l]);
    const colors = labels.map(l => ({malicious:'#ef4444',suspicious:'#f59e0b',benign:'#10b981'}[l] || '#6b7280'));
    if (verdictChart) verdictChart.destroy();
    verdictChart = new Chart(document.getElementById('verdictChart'), {
        type: 'doughnut',
        data: { labels, datasets: [{ data, backgroundColor: colors }] },
        options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#e5e7eb' } } } },
    });
}
function renderActionChart(byAction) {
    const grouped = {};
    for (const [k, v] of Object.entries(byAction || {})) {
        const key = k.split(' (')[0].split(' [')[0];
        grouped[key] = (grouped[key] || 0) + v;
    }
    const labels = Object.keys(grouped);
    const data = labels.map(l => grouped[l]);
    const colors = labels.map(l => l.includes('AUTO-BLOCK') ? '#ef4444' : l.includes('ESCALATE') ? '#f59e0b' : '#10b981');
    if (actionChart) actionChart.destroy();
    actionChart = new Chart(document.getElementById('actionChart'), {
        type: 'bar',
        data: { labels, datasets: [{ data, backgroundColor: colors }] },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#9ca3af' }, grid: { color: '#1f2937' } }, y: { ticks: { color: '#9ca3af' }, grid: { color: '#1f2937' } } } },
    });
}
function renderTable(decisions) {
    document.getElementById('decisionsBody').innerHTML = decisions.map(d => {
        const time = new Date(d.triaged_at).toLocaleTimeString();
        const conf = Math.round(d.confidence * 100) + '%';
        const actionClass = d.action_taken.includes('OVERRIDE') ? 'action override' : 'action';
        let agreement = '';
        const agreementMatch = (d.reasoning || '').match(/^\\[(UNANIMOUS|MAJORITY|SPLIT)\\]/);
        if (agreementMatch) {
            const cls = agreementMatch[1].toLowerCase();
            agreement = `<div class="agreement ${cls}">${agreementMatch[1]}</div>`;
        }
        return `<tr><td style="color:#9ca3af">${time}</td><td>${esc(d.agent)}</td><td>${esc(d.rule)}</td><td><span class="badge badge-${d.verdict}">${d.verdict}</span>${agreement}</td><td>${conf}</td><td class="${actionClass}">${esc(d.action_taken)}</td></tr>`;
    }).join('');
}
function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
fetchData();
setInterval(fetchData, 10000);
</script>
</body>
</html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Live HTML dashboard — stats, charts, recent decisions."""
    return DASHBOARD_HTML