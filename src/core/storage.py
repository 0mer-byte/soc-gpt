"""SQLite decision log — persists every triage decision for audit + dashboard."""

import sqlite3
from datetime import datetime
from pathlib import Path


DB_PATH = Path(__file__).parent.parent.parent / "data" / "soc_gpt.db"


class DecisionStore:
    """Stores and queries triage decisions in SQLite."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(exist_ok=True)

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasoning TEXT,
                    recommended TEXT,
                    action_taken TEXT NOT NULL,
                    llm_name TEXT NOT NULL,
                    triaged_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON decisions(verdict)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_triaged_at ON decisions(triaged_at)")

    def log_decision(self, alert_id, agent, rule, verdict, confidence,
                     reasoning, recommended, action_taken, llm_name):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO decisions
                (alert_id, agent, rule, verdict, confidence, reasoning,
                 recommended, action_taken, llm_name, triaged_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (alert_id, agent, rule, verdict, confidence, reasoning,
                  recommended, action_taken, llm_name, datetime.utcnow().isoformat()))

    def get_recent(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM decisions ORDER BY triaged_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
            by_verdict = dict(conn.execute(
                "SELECT verdict, COUNT(*) FROM decisions GROUP BY verdict"
            ).fetchall())
            by_action = dict(conn.execute(
                "SELECT action_taken, COUNT(*) FROM decisions GROUP BY action_taken"
            ).fetchall())
            avg_conf = conn.execute("SELECT AVG(confidence) FROM decisions").fetchone()[0] or 0.0
        return {
            "total_alerts": total,
            "by_verdict": by_verdict,
            "by_action": by_action,
            "average_confidence": round(avg_conf, 2),
        }