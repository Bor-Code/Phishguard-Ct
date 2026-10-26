import sqlite3
from typing import Callable, Dict

MIGRATION_STEP_1_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS flagged_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    target_brand TEXT NOT NULL,
    matched_term TEXT NOT NULL,
    composite_score REAL NOT NULL,
    score_levenshtein REAL NOT NULL,
    score_keyboard REAL NOT NULL,
    score_homoglyph REAL NOT NULL,
    score_affix REAL NOT NULL,
    is_live INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER,
    final_url TEXT,
    cert_issuer TEXT,
    cert_age_hours REAL,
    is_free_ca INTEGER NOT NULL DEFAULT 0,
    has_password_input INTEGER NOT NULL DEFAULT 0,
    has_login_form INTEGER NOT NULL DEFAULT 0,
    page_title TEXT,
    confidence_multiplier REAL NOT NULL DEFAULT 1.0,
    final_confidence_score REAL NOT NULL,
    risk_factors TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'flagged',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_flagged_domain ON flagged_domains(domain);
CREATE INDEX IF NOT EXISTS idx_flagged_brand ON flagged_domains(target_brand);
CREATE INDEX IF NOT EXISTS idx_flagged_final_score ON flagged_domains(final_confidence_score);
CREATE INDEX IF NOT EXISTS idx_flagged_status ON flagged_domains(status);
"""


def get_applied_versions(connection: sqlite3.Connection) -> set[int]:
    cursor = connection.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    )
    if not cursor.fetchone():
        return set()
    cursor.execute("SELECT version FROM schema_migrations")
    return {row[0] for row in cursor.fetchall()}


def apply_migration_1(connection: sqlite3.Connection) -> None:
    connection.executescript(MIGRATION_STEP_1_SQL)
    connection.execute("INSERT INTO schema_migrations (version) VALUES (1)")


MIGRATIONS: Dict[int, Callable[[sqlite3.Connection], None]] = {
    1: apply_migration_1,
}


def run_migrations(connection: sqlite3.Connection) -> None:
    applied = get_applied_versions(connection)
    for version in sorted(MIGRATIONS.keys()):
        if version not in applied:
            MIGRATIONS[version](connection)
            connection.commit()
