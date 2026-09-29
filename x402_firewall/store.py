"""Persistent storage for the x402 payment firewall.

A small, standard-library-only storage layer backed by SQLite (via
``sqlite3``). It keeps three tables:

* ``nonces``   — consumed nonces (PRIMARY KEY makes replay detection atomic).
* ``spend``    — approved-spend ledger, summed for the cumulative budget.
* ``decisions``— audit trail of every gate decision.

The database path is supplied by configuration. The special sentinel
``":memory:"`` opens an in-memory database (useful for tests). The schema is
created idempotently on open.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional, Tuple

MEMORY_DB = ":memory:"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    pay_to     TEXT NOT NULL,
    amount     REAL NOT NULL,
    decision   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS spend (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    amount     REAL NOT NULL,
    asset      TEXT NOT NULL,
    network    TEXT NOT NULL,
    pay_to     TEXT NOT NULL,
    payee      TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    request_fingerprint TEXT NOT NULL,
    verdict             TEXT NOT NULL,
    rule                TEXT,
    reason              TEXT,
    amount              REAL,
    pay_to              TEXT,
    payee               TEXT,
    nonce               TEXT,
    asset               TEXT,
    network             TEXT,
    source_url          TEXT,
    signed_payload_present INTEGER NOT NULL DEFAULT 0,
    decision_duration_ms   INTEGER,
    approved            INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL
);
"""

# Additive columns for the ``decisions`` audit table. Column names/types come
# from this hardcoded constant map (never user input); values are always bound
# as parameters. New databases get them from ``_SCHEMA`` above; existing
# databases get them via idempotent ``ALTER TABLE ... ADD COLUMN``.
_DECISION_ADDITIVE_COLUMNS = {
    "asset": "TEXT",
    "network": "TEXT",
    "source_url": "TEXT",
    "signed_payload_present": "INTEGER NOT NULL DEFAULT 0",
    "decision_duration_ms": "INTEGER",
}


def _now() -> str:
    """Return a UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply additive schema migrations idempotently.

    Adds any missing audit columns to existing databases so old DBs keep
    opening after a code upgrade. Column names/types are drawn from the
    hardcoded ``_DECISION_ADDITIVE_COLUMNS`` map, never from user input.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(decisions)")}
    for column, decl in _DECISION_ADDITIVE_COLUMNS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE decisions ADD COLUMN {column} {decl}")


class Store:
    """SQLite-backed nonce + spend + audit store.

    Can be used as a context manager::

        with Store("x402_firewall.db") as store:
            store.record_nonce(...)
    """

    def __init__(self, path: str = MEMORY_DB) -> None:
        self.path = path
        # check_same_thread=False lets each thread use its own connection to
        # the same file; SQLite's locking serialises writers.
        self._conn = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._conn.isolation_level = None  # autocommit; we manage transactions.
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        _migrate(self._conn)

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    # -- nonces -------------------------------------------------------------
    def nonce_seen(self, nonce: str) -> bool:
        """Return True if the nonce has already been consumed."""
        cur = self._conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
        return cur.fetchone() is not None

    def record_nonce(self, nonce: str, pay_to: str, amount: float, decision: str) -> bool:
        """Record a consumed nonce. Return False if it was already present.

        The PRIMARY KEY constraint makes duplicate recording safe across
        processes and threads.
        """
        try:
            self._conn.execute(
                "INSERT INTO nonces (nonce, pay_to, amount, decision, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (nonce, pay_to, amount, decision, _now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    # -- spend ledger -------------------------------------------------------
    def record_spend(
        self, amount: float, asset: str, network: str, pay_to: str, payee: str, nonce: str
    ) -> None:
        """Append a spend ledger row.

        The ``nonce`` column is ``NOT NULL``; v2-derived requests legitimately
        carry no nonce (replay protection happens on the signed authorization),
        so a ``None`` nonce is recorded as the empty string in the ledger.
        """
        self._conn.execute(
            "INSERT INTO spend (amount, asset, network, pay_to, payee, nonce, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (amount, asset, network, pay_to, payee, nonce if nonce is not None else "", _now()),
        )

    def total_spent(self) -> float:
        """Return the cumulative approved spend across the ledger."""
        cur = self._conn.execute("SELECT COALESCE(SUM(amount), 0.0) FROM spend")
        return float(cur.fetchone()[0])

    def record_pay(
        self,
        nonce: str,
        pay_to: str,
        amount: float,
        asset: str,
        network: str,
        payee: str,
        total_budget: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], float]:
        """Atomically commit a PAY: insert nonce + spend in one transaction.

        Uses ``BEGIN IMMEDIATE`` so two simultaneous evaluations of the same
        nonce, or a double-spend near the cumulative cap, cannot both succeed.

        Returns ``(ok, rule, already_spent)``:
            * ``(True, None, ...)``   — payment committed.
            * ``(False, "nonce_replay", 0.0)``     — nonce already consumed.
            * ``(False, "total_budget", already)`` — would exceed the cap.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            try:
                self._conn.execute(
                    "INSERT INTO nonces (nonce, pay_to, amount, decision, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (nonce, pay_to, amount, "PAY", _now()),
                )
            except sqlite3.IntegrityError:
                self._conn.execute("ROLLBACK")
                return False, "nonce_replay", 0.0

            if total_budget is not None:
                cur = self._conn.execute(
                    "SELECT COALESCE(SUM(amount), 0.0) FROM spend"
                )
                already = float(cur.fetchone()[0])
                if already + amount > total_budget:
                    self._conn.execute("ROLLBACK")
                    return False, "total_budget", already

            self._conn.execute(
                "INSERT INTO spend (amount, asset, network, pay_to, payee, nonce, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    amount,
                    asset,
                    network,
                    pay_to,
                    payee,
                    nonce if nonce is not None else "",
                    _now(),
                ),
            )
            self._conn.execute("COMMIT")
            return True, None, 0.0
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    # -- audit trail --------------------------------------------------------
    def record_decision(
        self,
        *,
        request_fingerprint: str,
        verdict: str,
        rule: Optional[str],
        reason: Optional[str],
        amount: Optional[float],
        pay_to: Optional[str],
        payee: Optional[str],
        nonce: Optional[str],
        approved: bool = False,
        asset: Optional[str] = None,
        network: Optional[str] = None,
        source_url: Optional[str] = None,
        signed_payload_present: bool = False,
        decision_duration_ms: Optional[int] = None,
    ) -> None:
        """Append an audit row describing one gate decision."""
        self._conn.execute(
            "INSERT INTO decisions "
            "(request_fingerprint, verdict, rule, reason, amount, pay_to, payee, "
            " nonce, asset, network, source_url, signed_payload_present, "
            " decision_duration_ms, approved, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request_fingerprint,
                verdict,
                rule,
                reason,
                amount,
                pay_to,
                payee,
                nonce,
                asset,
                network,
                source_url,
                1 if signed_payload_present else 0,
                decision_duration_ms,
                1 if approved else 0,
                _now(),
            ),
        )

    def decisions(self):
        """Return all audit rows, oldest first, as a list of dicts."""
        rows = self._conn.execute(
            "SELECT * FROM decisions ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def list_decisions(
        self,
        limit: Optional[int] = None,
        verdict: Optional[str] = None,
        since: Optional[str] = None,
    ):
        """Return audit rows, newest first, optionally filtered.

        ``limit`` caps the row count; ``verdict`` filters by PAY/ASK/DENY;
        ``since`` is an ISO-8601 timestamp (rows at or after it). All filter
        values are bound as SQL parameters (no string interpolation).
        """
        clauses = []
        params: list = []
        if verdict is not None:
            clauses.append("verdict = ?")
            params.append(verdict)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since)
        sql = "SELECT * FROM decisions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
