import asyncio
import logging
from typing import Any, Dict, List, Optional
from phishguard.alerting import WebhookAlerter
from phishguard.config import Settings
from phishguard.evaluation.datasets import extract_domain_from_url
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
            provider=self.settings.alert_provider,
            telegram_chat_id=self.settings.telegram_chat_id,
        )

        self.event_queue: asyncio.Queue[CertificateEvent] = asyncio.Queue()
        self.client = certstream_client or None
        self._running = False
        self._consumer_task: Optional[asyncio.Task] = None

    def _get_client(self) -> CertstreamClient:
        if self.client is None:
            self.client = CertstreamClient(
                url=self.settings.certstream_url,
                queue=self.event_queue,
            )
        return self.client

    async def inspect_domain(
        self,
        raw_input: str,
        verify: bool = True,
        persist: bool = False,
    ) -> Dict[str, Any]:
        extracted = extract_domain_from_url(raw_input) or raw_input.strip().lower()
        is_legitimate = self.watchlist.is_legitimate_domain(extracted)
        score_result = self.scoring_engine.score_domain(
            extracted, self.watchlist.all_brands()
        )

        if score_result is None:
            return {
                "domain": extracted,
                "is_legitimate": is_legitimate,
                "is_phishing_suspect": False,
                "target_brand": None,
                "matched_term": "",
                "composite_score": 0.0,
                "final_confidence_score": 0.0,
                "signals": {
                    "levenshtein": 0.0,
                    "keyboard": 0.0,
                    "homoglyph": 0.0,
                    "subdomain_or_affix": 0.0,
                },
                "verification": None,
            }

        is_suspect = (not is_legitimate) and score_result.is_phishing_suspect
        verification_data: Optional[Dict[str, Any]] = None
        final_score = 0.0 if is_legitimate else score_result.composite_score

        if verify and not is_legitimate:
            verification = await self.verifier.verify_domain(
                domain=extracted,
                target_brand=score_result.target_brand,
            )
            final_score = min(
                1.0,
                round(score_result.composite_score * verification.confidence_multiplier, 4),
            )
            verification_data = {
                "is_reachable": verification.is_reachable,
                "status_code": verification.status_code,
                "final_url": verification.final_url,
                "page_title": verification.content.page_title,
                "has_password_input": verification.content.has_password_input,
                "has_login_form": verification.content.has_login_form,
                "confidence_multiplier": verification.confidence_multiplier,
                "risk_factors": verification.risk_factors,
            }

            if persist and is_suspect:
                self.database.initialize()
                record = FlaggedRecord(
                    domain=extracted,
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
        elif persist and is_suspect:
            self.database.initialize()
            record = FlaggedRecord(
                domain=extracted,
                target_brand=score_result.target_brand,
                matched_term=score_result.matched_term,
                composite_score=score_result.composite_score,
                score_levenshtein=score_result.signals.levenshtein,
                score_keyboard=score_result.signals.keyboard,
                score_homoglyph=score_result.signals.homoglyph,
                score_affix=score_result.signals.subdomain_or_affix,
                confidence_multiplier=1.0,
                final_confidence_score=final_score,
                status="flagged",
            )
            self.database.record_detection(record)

        return {
            "domain": extracted,
            "is_legitimate": is_legitimate,
            "is_phishing_suspect": is_suspect,
            "target_brand": score_result.target_brand,
            "matched_term": score_result.matched_term,
            "composite_score": score_result.composite_score,
            "final_confidence_score": final_score,
            "signals": {
                "levenshtein": score_result.signals.levenshtein,
                "keyboard": score_result.signals.keyboard,
                "homoglyph": score_result.signals.homoglyph,
                "subdomain_or_affix": score_result.signals.subdomain_or_affix,
            },
            "verification": verification_data,
        }

    async def process_domain(
        self, domain: str, event: CertificateEvent
    ) -> Optional[FlaggedRecord]:
        if self.watchlist.is_legitimate_domain(domain):
            return None

        score_result = self.scoring_engine.score_domain(
            domain, self.watchlist.all_brands()
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
        client = self._get_client()
        await client.start()
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
        if self.client is not None:
            await self.client.stop()
        self.database.close()
