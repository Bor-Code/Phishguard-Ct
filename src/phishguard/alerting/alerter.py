import logging
from typing import Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from phishguard.alerting.payload import detect_webhook_provider, format_alert_payload
from phishguard.storage.models import FlaggedRecord

logger = logging.getLogger("phishguard.alerting")


class WebhookAlerter:
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        min_alert_score: float = 0.75,
        timeout_seconds: float = 5.0,
        provider: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ) -> None:
        self.webhook_url = webhook_url.strip() if webhook_url else None
        self.min_alert_score = min_alert_score
        self.timeout_seconds = timeout_seconds
        self.provider = detect_webhook_provider(self.webhook_url, provider)
        self.telegram_chat_id = telegram_chat_id.strip() if telegram_chat_id else None
        self.timeout = (
            aiohttp.ClientTimeout(total=timeout_seconds)
            if aiohttp is not None
            else None
        )

    def should_alert(self, record: FlaggedRecord) -> bool:
        return record.final_confidence_score >= self.min_alert_score

    async def send_alert(self, record: FlaggedRecord) -> bool:
        if not self.should_alert(record):
            return False

        logger.warning(
            "High confidence phishing detected: domain=%s brand=%s score=%.4f live=%s",
            record.domain,
            record.target_brand,
            record.final_confidence_score,
            record.is_live,
        )

        if not self.webhook_url:
            return True

        if aiohttp is None:
            logger.error("aiohttp is required to deliver webhook alerts")
            return False

        payload = format_alert_payload(
            record,
            provider=self.provider,
            chat_id=self.telegram_chat_id,
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status < 300:
                        logger.info(
                            "Webhook alert delivered successfully for domain %s via %s (status=%d)",
                            record.domain,
                            self.provider,
                            response.status,
                        )
                        return True
                    logger.error(
                        "Webhook alert delivery failed for domain %s with status %d",
                        record.domain,
                        response.status,
                    )
                    return False
        except Exception as error:
            logger.error(
                "Webhook alert delivery encountered network error for domain %s: %s",
                record.domain,
                error,
            )
            return False
