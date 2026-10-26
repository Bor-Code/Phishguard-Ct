import asyncio
import pytest
from phishguard.alerting import WebhookAlerter
from phishguard.cli import build_parser
from phishguard.config import Settings
from phishguard.ingestion import CertificateEvent
from phishguard.scoring import ScoringEngine
from phishguard.service import PhishGuardService
from phishguard.storage import DatabaseManager
from phishguard.verification import DomainVerifier, VerificationResult
from phishguard.watchlist import BrandWatchlist


class MockDomainVerifier(DomainVerifier):
    async def verify_domain(
        self,
        domain: str,
        target_brand=None,
        issuer=None,
        not_before=None,
        not_after=None,
    ) -> VerificationResult:
        is_live = "offline" not in domain
        return VerificationResult(
            domain=domain,
            is_reachable=is_live,
            status_code=200 if is_live else None,
            final_url=f"https://{domain}/login" if is_live else None,
            confidence_multiplier=1.2 if is_live else 1.0,
            risk_factors=["password_input_detected"] if is_live else [],
        )


@pytest.mark.asyncio
async def test_service_process_event_flow():
    database = DatabaseManager(database_path=":memory:")
    alerter = WebhookAlerter(webhook_url=None, min_alert_score=0.75)
    verifier = MockDomainVerifier()
    watchlist = BrandWatchlist.from_defaults()
    scoring = ScoringEngine(suspect_threshold=0.75)

    service = PhishGuardService(
        watchlist=watchlist,
        scoring_engine=scoring,
        verifier=verifier,
        database=database,
        alerter=alerter,
    )
    service.database.initialize()

    event = CertificateEvent(
        domains=["paypa1-secure-center.com", "wikipedia.org", "paypal.com"],
        issuer="Let's Encrypt",
        not_before=1700000000.0,
        not_after=1710000000.0,
    )

    flagged_records = await service.process_event(event)

    assert len(flagged_records) == 1
    record = flagged_records[0]
    assert record.domain == "paypa1-secure-center.com"
    assert record.target_brand == "paypal"
    assert record.is_live is True

    stored = service.database.get_domain("paypa1-secure-center.com")
    assert stored is not None
    assert stored.status == "alert_sent"
    assert service.database.get_domain("wikipedia.org") is None
    assert service.database.get_domain("paypal.com") is None


@pytest.mark.asyncio
async def test_service_start_and_consume():
    database = DatabaseManager(database_path=":memory:")
    alerter = WebhookAlerter(webhook_url=None, min_alert_score=0.75)
    verifier = MockDomainVerifier()

    service = PhishGuardService(
        verifier=verifier,
        database=database,
        alerter=alerter,
    )
    service.database.initialize()

    sample_event = CertificateEvent(
        domains=["g00gle-accounts-login.xyz"],
        issuer="Let's Encrypt",
    )
    await service.event_queue.put(sample_event)

    service._running = True
    await service._consume_queue(max_events=1)

    record = service.database.get_domain("g00gle-accounts-login.xyz")
    assert record is not None
    assert record.target_brand == "google"


def test_cli_parser_options():
    parser = build_parser()

    monitor_args = parser.parse_args(["monitor", "--url", "wss://test.stream", "--max-events", "10"])
    assert monitor_args.command == "monitor"
    assert monitor_args.url == "wss://test.stream"
    assert monitor_args.max_events == 10

    eval_args = parser.parse_args(["evaluate", "--threshold", "0.80"])
    assert eval_args.command == "evaluate"
    assert eval_args.threshold == 0.80

    list_args = parser.parse_args(["list", "--brand", "paypal", "--limit", "50"])
    assert list_args.command == "list"
    assert list_args.brand == "paypal"
    assert list_args.limit == 50
