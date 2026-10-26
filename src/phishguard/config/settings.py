import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    certstream_url: str = "wss://api.certstream.dev/domains-only"
    alert_webhook_url: Optional[str] = None
    database_path: str = "phishguard.db"
    log_level: str = "INFO"
    min_alert_score: float = 0.75
    watchlist_path: Optional[str] = None
    http_timeout_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        webhook_raw = os.getenv("ALERT_WEBHOOK_URL", "").strip()
        alert_webhook = webhook_raw if webhook_raw else None
        watchlist_raw = os.getenv("WATCHLIST_PATH", "").strip()
        watchlist_path = watchlist_raw if watchlist_raw else None

        min_score_raw = os.getenv("MIN_ALERT_SCORE", "0.75").strip()
        try:
            min_alert_score = float(min_score_raw)
        except ValueError:
            min_alert_score = 0.75

        timeout_raw = os.getenv("HTTP_TIMEOUT_SECONDS", "5.0").strip()
        try:
            http_timeout = float(timeout_raw)
        except ValueError:
            http_timeout = 5.0

        return cls(
            certstream_url=os.getenv(
                "CERTSTREAM_URL", "wss://api.certstream.dev/domains-only"
            ).strip(),
            alert_webhook_url=alert_webhook,
            database_path=os.getenv("DATABASE_PATH", "phishguard.db").strip(),
            log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
            min_alert_score=min_alert_score,
            watchlist_path=watchlist_path,
            http_timeout_seconds=http_timeout,
        )
