import json
from pathlib import Path
import sqlite3
from typing import List, Optional, Union
from phishguard.storage.migrations import run_migrations
from phishguard.storage.models import FlaggedRecord


class DatabaseManager:
    def __init__(self, database_path: Union[str, Path] = "phishguard.db") -> None:
        self.database_path = str(database_path)
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(
                self.database_path,
                timeout=30.0,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            if self.database_path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    def initialize(self) -> None:
        connection = self.connect()
        run_migrations(connection)

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "DatabaseManager":
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _row_to_record(self, row: sqlite3.Row) -> FlaggedRecord:
        risk_factors_raw = row["risk_factors"]
        try:
            risk_factors = json.loads(risk_factors_raw) if risk_factors_raw else []
        except (json.JSONDecodeError, TypeError):
            risk_factors = []

        return FlaggedRecord(
            id=row["id"],
            domain=row["domain"],
            target_brand=row["target_brand"],
            matched_term=row["matched_term"],
            composite_score=float(row["composite_score"]),
            score_levenshtein=float(row["score_levenshtein"]),
            score_keyboard=float(row["score_keyboard"]),
            score_homoglyph=float(row["score_homoglyph"]),
            score_affix=float(row["score_affix"]),
            is_live=bool(row["is_live"]),
            http_status=row["http_status"],
            final_url=row["final_url"],
            cert_issuer=row["cert_issuer"],
            cert_age_hours=row["cert_age_hours"],
            is_free_ca=bool(row["is_free_ca"]),
            has_password_input=bool(row["has_password_input"]),
            has_login_form=bool(row["has_login_form"]),
            page_title=row["page_title"],
            confidence_multiplier=float(row["confidence_multiplier"]),
            final_confidence_score=float(row["final_confidence_score"]),
            risk_factors=risk_factors,
            status=row["status"],
            detected_at=row["detected_at"],
            updated_at=row["updated_at"],
        )

    def record_detection(self, record: FlaggedRecord) -> int:
        connection = self.connect()
        risk_factors_json = json.dumps(record.risk_factors)
        query = """
        INSERT INTO flagged_domains (
            domain, target_brand, matched_term, composite_score,
            score_levenshtein, score_keyboard, score_homoglyph, score_affix,
            is_live, http_status, final_url, cert_issuer, cert_age_hours,
            is_free_ca, has_password_input, has_login_form, page_title,
            confidence_multiplier, final_confidence_score, risk_factors,
            status, updated_at
        ) VALUES (
            :domain, :target_brand, :matched_term, :composite_score,
            :score_levenshtein, :score_keyboard, :score_homoglyph, :score_affix,
            :is_live, :http_status, :final_url, :cert_issuer, :cert_age_hours,
            :is_free_ca, :has_password_input, :has_login_form, :page_title,
            :confidence_multiplier, :final_confidence_score, :risk_factors,
            :status, CURRENT_TIMESTAMP
        )
        ON CONFLICT(domain) DO UPDATE SET
            target_brand = excluded.target_brand,
            matched_term = excluded.matched_term,
            composite_score = excluded.composite_score,
            score_levenshtein = excluded.score_levenshtein,
            score_keyboard = excluded.score_keyboard,
            score_homoglyph = excluded.score_homoglyph,
            score_affix = excluded.score_affix,
            is_live = excluded.is_live,
            http_status = excluded.http_status,
            final_url = excluded.final_url,
            cert_issuer = excluded.cert_issuer,
            cert_age_hours = excluded.cert_age_hours,
            is_free_ca = excluded.is_free_ca,
            has_password_input = excluded.has_password_input,
            has_login_form = excluded.has_login_form,
            page_title = excluded.page_title,
            confidence_multiplier = excluded.confidence_multiplier,
            final_confidence_score = excluded.final_confidence_score,
            risk_factors = excluded.risk_factors,
            status = excluded.status,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id;
        """
        params = {
            "domain": record.domain,
            "target_brand": record.target_brand,
            "matched_term": record.matched_term,
            "composite_score": record.composite_score,
            "score_levenshtein": record.score_levenshtein,
            "score_keyboard": record.score_keyboard,
            "score_homoglyph": record.score_homoglyph,
            "score_affix": record.score_affix,
            "is_live": int(record.is_live),
            "http_status": record.http_status,
            "final_url": record.final_url,
            "cert_issuer": record.cert_issuer,
            "cert_age_hours": record.cert_age_hours,
            "is_free_ca": int(record.is_free_ca),
            "has_password_input": int(record.has_password_input),
            "has_login_form": int(record.has_login_form),
            "page_title": record.page_title,
            "confidence_multiplier": record.confidence_multiplier,
            "final_confidence_score": record.final_confidence_score,
            "risk_factors": risk_factors_json,
            "status": record.status,
        }
        cursor = connection.execute(query, params)
        row = cursor.fetchone()
        connection.commit()
        return row[0]

    def get_domain(self, domain: str) -> Optional[FlaggedRecord]:
        connection = self.connect()
        query = "SELECT * FROM flagged_domains WHERE domain = ?"
        cursor = connection.execute(query, (domain,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def list_flagged(
        self,
        min_score: float = 0.0,
        target_brand: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[FlaggedRecord]:
        connection = self.connect()
        clauses = ["final_confidence_score >= ?"]
        params: List[Union[float, str, int]] = [min_score]

        if target_brand:
            clauses.append("target_brand = ?")
            params.append(target_brand.lower())
        if status:
            clauses.append("status = ?")
            params.append(status)

        params.append(limit)
        where_clause = " AND ".join(clauses)
        query = f"SELECT * FROM flagged_domains WHERE {where_clause} ORDER BY final_confidence_score DESC LIMIT ?"
        cursor = connection.execute(query, params)
        return [self._row_to_record(row) for row in cursor.fetchall()]

    def update_status(self, domain: str, new_status: str) -> bool:
        connection = self.connect()
        query = "UPDATE flagged_domains SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE domain = ?"
        cursor = connection.execute(query, (new_status, domain))
        connection.commit()
        return cursor.rowcount > 0

    def count_flagged(self, status: Optional[str] = None) -> int:
        connection = self.connect()
        if status:
            cursor = connection.execute(
                "SELECT COUNT(*) FROM flagged_domains WHERE status = ?", (status,)
            )
        else:
            cursor = connection.execute("SELECT COUNT(*) FROM flagged_domains")
        return cursor.fetchone()[0]
