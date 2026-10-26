import pytest
from aiohttp import web
from phishguard.alerting import WebhookAlerter, format_alert_payload
from phishguard.storage.models import FlaggedRecord


def create_record(score: float = 0.85) -> FlaggedRecord:
    return FlaggedRecord(
        domain="paypa1-update.com",
        target_brand="paypal",
        matched_term="paypa1",
        composite_score=0.80,
        score_levenshtein=0.83,
        score_keyboard=0.92,
        score_homoglyph=1.0,
        score_affix=0.85,
        is_live=True,
        http_status=200,
        final_url="https://paypa1-update.com/login",
        cert_issuer="Let's Encrypt",
        cert_age_hours=1.2,
        is_free_ca=True,
        has_password_input=True,
        has_login_form=True,
        page_title="Login - PayPal",
        confidence_multiplier=1.25,
        final_confidence_score=score,
        risk_factors=["password_input_detected", "newly_issued_certificate"],
        status="flagged",
    )


def test_format_alert_payload():
    record = create_record(score=0.92)
    payload = format_alert_payload(record)
    assert payload["event"] == "phishing_alert"
    assert payload["domain"] == "paypa1-update.com"
    assert payload["target_brand"] == "paypal"
    assert payload["final_confidence_score"] == 0.92
    assert "paypa1-update.com" in payload["content"]
    assert "paypa1-update.com" in payload["text"]
    assert len(payload["embeds"]) == 1
    assert payload["details"]["matched_term"] == "paypa1"


def test_alerter_should_alert():
    alerter = WebhookAlerter(min_alert_score=0.75)
    assert alerter.should_alert(create_record(score=0.85)) is True
    assert alerter.should_alert(create_record(score=0.75)) is True
    assert alerter.should_alert(create_record(score=0.74)) is False


@pytest.mark.asyncio
async def test_alerter_log_only():
    alerter = WebhookAlerter(webhook_url=None, min_alert_score=0.75)
    result_high = await alerter.send_alert(create_record(score=0.90))
    assert result_high is True

    result_low = await alerter.send_alert(create_record(score=0.50))
    assert result_low is False


@pytest.mark.asyncio
async def test_alerter_webhook_success(unused_tcp_port):
    received_payloads = []

    async def webhook_handler(request):
        data = await request.json()
        received_payloads.append(data)
        return web.json_response({"ok": True}, status=200)

    app = web.Application()
    app.router.add_post("/webhook", webhook_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()

    try:
        url = f"http://127.0.0.1:{unused_tcp_port}/webhook"
        alerter = WebhookAlerter(webhook_url=url, min_alert_score=0.75)
        record = create_record(score=0.88)

        success = await alerter.send_alert(record)
        assert success is True
        assert len(received_payloads) == 1
        assert received_payloads[0]["domain"] == "paypa1-update.com"
        assert received_payloads[0]["target_brand"] == "paypal"
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_alerter_webhook_failure(unused_tcp_port):
    async def error_handler(request):
        return web.Response(text="Internal Error", status=500)

    app = web.Application()
    app.router.add_post("/webhook", error_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()

    try:
        url = f"http://127.0.0.1:{unused_tcp_port}/webhook"
        alerter = WebhookAlerter(webhook_url=url, min_alert_score=0.75)
        success = await alerter.send_alert(create_record(score=0.88))
        assert success is False
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_alerter_webhook_unreachable():
    alerter = WebhookAlerter(
        webhook_url="http://127.0.0.1:59998/webhook",
        min_alert_score=0.75,
        timeout_seconds=0.5,
    )
    success = await alerter.send_alert(create_record(score=0.88))
    assert success is False
