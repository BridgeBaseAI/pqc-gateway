"""
Database layer — SQLite for local/dev, swap connection string for Supabase/Postgres.
"""

import sqlite3
from typing import Optional

from models import AgentPassport


class Database:
    def __init__(self, db_path: str = "registry.db") -> None:
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")   # safe for concurrent reads
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agent_passports (
                    agent_id        TEXT PRIMARY KEY,
                    public_key      TEXT NOT NULL,
                    metadata        TEXT NOT NULL DEFAULT '{}',
                    registered_at   TEXT NOT NULL,
                    reputation_score INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS pqc_challenges (
                    challenge_id      TEXT PRIMARY KEY,
                    agent_id          TEXT NOT NULL,
                    shared_secret_b64 TEXT NOT NULL,
                    expires_at        REAL NOT NULL,
                    used              INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (agent_id) REFERENCES agent_passports (agent_id)
                );

                CREATE INDEX IF NOT EXISTS idx_challenges_agent
                    ON pqc_challenges (agent_id);
            """)

    # ------------------------------------------------------------------
    # Passports
    # ------------------------------------------------------------------

    def save_passport(self, passport: AgentPassport) -> None:
        import json
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT agent_id FROM agent_passports WHERE agent_id = ?",
                (passport.agent_id,),
            ).fetchone()
            if existing:
                raise ValueError(f"Agent '{passport.agent_id}' already registered.")

            conn.execute(
                """
                INSERT INTO agent_passports
                    (agent_id, public_key, metadata, registered_at, reputation_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    passport.agent_id,
                    passport.public_key,
                    json.dumps(passport.metadata),
                    passport.registered_at,
                    passport.reputation_score,
                ),
            )

    def get_passport(self, agent_id: str) -> Optional[AgentPassport]:
        import json
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM agent_passports WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        return AgentPassport(
            agent_id=row["agent_id"],
            public_key=row["public_key"],
            metadata=json.loads(row["metadata"]),
            registered_at=row["registered_at"],
            reputation_score=row["reputation_score"],
        )

    def increment_reputation(self, agent_id: str) -> int:
        with self._conn() as conn:
            conn.execute(
                "UPDATE agent_passports SET reputation_score = reputation_score + 1 WHERE agent_id = ?",
                (agent_id,),
            )
            row = conn.execute(
                "SELECT reputation_score FROM agent_passports WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        return row["reputation_score"] if row else 0

    # ------------------------------------------------------------------
    # Challenges
    # ------------------------------------------------------------------

    def save_challenge(
        self,
        challenge_id: str,
        agent_id: str,
        shared_secret_b64: str,
        expires_at: float,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO pqc_challenges
                    (challenge_id, agent_id, shared_secret_b64, expires_at, used)
                VALUES (?, ?, ?, ?, 0)
                """,
                (challenge_id, agent_id, shared_secret_b64, expires_at),
            )

    def get_challenge(self, challenge_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pqc_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def mark_challenge_used(self, challenge_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE pqc_challenges SET used = 1 WHERE challenge_id = ?",
                (challenge_id,),
            )

    def list_agents(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT agent_id FROM agent_passports ORDER BY registered_at DESC"
            ).fetchall()
        return [row["agent_id"] for row in rows]
