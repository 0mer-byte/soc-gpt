"""FastAPI webhook server — receives security alerts and triages them."""

import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel, Field

from src.core.response import route_decision
from src.core.storage import DecisionStore
from src.llm.ollama_provider import OllamaProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

llm: OllamaProvider | None = None
store: DecisionStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup."""
    global llm, store
    llm = OllamaProvider()
    store = DecisionStore()
    store.init_db()
    logger.info("SOC-GPT ready — LLM=%s", llm.name)
    yield
    logger.info("SOC-GPT shutting down")


app = FastAPI(
    title="SOC-GPT 2.0 API",
    description="AI-powered SIEM alert triage",
    version="0.1.0",
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
        "llm": llm.name if llm else "not initialized",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/webhook/alert")
async def receive_alert(alert: AlertWebhook):
    """Receive an alert, triage it, store decision, return action."""
    logger.info("Received alert %s: %s", alert.alert_id, alert.rule_description)

    alert_dict = alert.model_dump()
    decision = await llm.analyze_alert(alert_dict)
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
        llm_name=llm.name,
    )

    return {
        "alert_id": alert.alert_id,
        "verdict": decision.verdict,
        "confidence": decision.confidence,
        "reasoning": decision.reasoning,
        "action_taken": action,
    }


@app.get("/decisions")
async def list_decisions(limit: int = 20):
    """Return recent triage decisions."""
    return {"decisions": store.get_recent(limit)}


@app.get("/stats")
async def stats():
    """Return overall triage statistics."""
    return store.get_stats()