import asyncio
import logging
from typing import List, Optional
from phishguard.alerting import WebhookAlerter
from phishguard.config import Settings
from phishguard.ingestion import CertificateEvent, CertstreamClient
from phishguard.scoring import ScoringEngine
from phishguard.storage import DatabaseManager, FlaggedRecord
from phishguard.verification import DomainVerifier
from phishguard.watchlist import BrandWatchlist

logger = logging.getLogger("phishguard.service")


class PhishGuardService:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        watchlist: Optional[BrandWatchlist] = None,
        scoring_engine: Optional[ScoringEngine] = None,
        verifier: Optional[DomainVerifier] = None,
        database: Optional[DatabaseManager] = None,
        alerter: Optional[WebhookAlerter] = None,
        certstream_client: Optional[CertstreamClient] = None,
    ) -> None:
        self.settings = settings or Settings.from_env()

        if watchlist is not None:
            self.watchlist = watchlist
        elif self.settings.watchlist_path:
            self.watchlist = BrandWatchlist.from_json_file(self.settings.watchlist_path)
        else:
            self.watchlist = BrandWatchlist.from_defaults()

        self.scoring_engine = scoring_engine or ScoringEngine(
            suspect_threshold=self.settings.min_alert_score
        )
        self.verifier = verifier or DomainVerifier(
            timeout_seconds=self.settings.http_timeout_seconds
        )
        self.database = database or DatabaseManager(
            database_path=self.settings.database_path
        )
        self.alerter = alerter or WebhookAlerter(
            webhook_url=self.settings.alert_webhook_url,
            min_alert_score=self.settings.min_alert_score,
        )

        self.event_queue: asyncio.Queue[CertificateEvent] = asyncio.Queue()
        self.client = certstream_client or CertstreamClient(
            url=self.settings.certstream_url,
            queue=self.event_queue,
        )
        self._running = False
        self._consumer_task: Optional[asyncio.Task] = None

    async def process_domain(
        self, domain: str, event: CertificateEvent
    ) -> Optional[FlaggedRecord]:
        if self.watchlist.is_legitimate_domain(domain):
            return None

        score_result = self.scoring_engine.score_domain(
            domain, self.watchlist.all_brand_names()
        )
        if not score_result or not score_result.is_phishing_suspect:
            return None

        verification = await self.verifier.verify_domain(
            domain=domain,
            target_brand=score_result.target_brand,
            issuer=event.issuer,
            not_before=event.not_before,
            not_after=event.not_after,
        )

        final_score = min(
            1.0,
            round(score_result.composite_score * verification.confidence_multiplier, 4),
        )

        record = FlaggedRecord(
            domain=domain,
            target_brand=score_result.target_brand,
            matched_term=score_result.matched_term,
            composite_score=score_result.composite_score,
            score_levenshtein=score_result.signals.levenshtein,
            score_keyboard=score_result.signals.keyboard,
            score_homoglyph=score_result.signals.homoglyph,
            score_affix=score_result.signals.subdomain_or_affix,
            is_live=verification.is_reachable,
            http_status=verification.status_code,
            final_url=verification.final_url,
            cert_issuer=verification.certificate.issuer,
            cert_age_hours=verification.certificate.age_hours,
            is_free_ca=verification.certificate.is_free_automated_ca,
            has_password_input=verification.content.has_password_input,
            has_login_form=verification.content.has_login_form,
            page_title=verification.content.page_title,
            confidence_multiplier=verification.confidence_multiplier,
            final_confidence_score=final_score,
            risk_factors=verification.risk_factors,
            status="flagged",
        )

        self.database.record_detection(record)

        if self.alerter.should_alert(record):
            alert_delivered = await self.alerter.send_alert(record)
            if alert_delivered:
                self.database.update_status(record.domain, "alert_sent")

        return record

    async def process_event(self, event: CertificateEvent) -> List[FlaggedRecord]:
        flagged: List[FlaggedRecord] = []
        for domain in event.domains:
            try:
                record = await self.process_domain(domain, event)
                if record is not None:
                    flagged.append(record)
            except Exception as error:
                logger.error("Error processing domain %s: %s", domain, error)
        return flagged

    async def _consume_queue(self, max_events: int = 0) -> None:
        processed_count = 0
        while self._running:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                await self.process_event(event)
                self.event_queue.task_done()
                processed_count += 1
                if max_events > 0 and processed_count >= max_events:
                    break
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def start(self, max_events: int = 0) -> None:
        self.database.initialize()
        self._running = True
        await self.client.start()
        self._consumer_task = asyncio.create_task(self._consume_queue(max_events=max_events))
        try:
            await self._consumer_task
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        self._running = False
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        await self.client.stop()
        self.database.close()
