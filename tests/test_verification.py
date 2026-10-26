import time
import pytest
from aiohttp import web
from phishguard.verification import (
    DomainVerifier,
    analyze_certificate,
    analyze_html_content,
    calculate_cert_age_hours,
    detect_login_forms,
    detect_password_inputs,
    extract_page_title,
    is_free_automated_ca,
)


def test_calculate_cert_age_hours():
    now = 1700000000.0
    issued_2_hours_ago = now - 7200
    assert calculate_cert_age_hours(issued_2_hours_ago, current_timestamp=now) == 2.0
    assert calculate_cert_age_hours(None) is None


def test_is_free_automated_ca():
    assert is_free_automated_ca("Let's Encrypt Authority R3") is True
    assert is_free_automated_ca("ZeroSSL RSA Domain Secure Site CA") is True
    assert is_free_automated_ca("Cloudflare Inc ECC CA-3") is True
    assert is_free_automated_ca("DigiCert Global Root G2") is False
    assert is_free_automated_ca(None) is False


def test_analyze_certificate_new_and_free():
    now = time.time()
    issued_recently = now - 3600
    meta = analyze_certificate(
        issuer="Let's Encrypt",
        not_before=issued_recently,
        not_after=now + 86400 * 90,
        current_timestamp=now,
        new_cert_threshold_hours=24.0,
    )
    assert meta.is_newly_issued is True
    assert meta.is_free_automated_ca is True
    assert meta.age_hours is not None
    assert meta.age_hours <= 1.1


def test_extract_page_title():
    html_sample = "<html><head><title>  Secure &amp; Sign In - PayPal  </title></head></html>"
    title = extract_page_title(html_sample)
    assert title == "Secure & Sign In - PayPal"


def test_detect_password_inputs():
    html_with_password = '<form><input type="text" name="user"><input type="password" name="pwd"></form>'
    html_without_password = '<form><input type="text" name="search"><button>Search</button></form>'
    assert detect_password_inputs(html_with_password) is True
    assert detect_password_inputs(html_without_password) is False


def test_detect_login_forms():
    html_login_form = '<form action="/verify"><input type="password"></form>'
    html_action_login = '<form action="https://phish.xyz/login.php"><input type="text"></form>'
    html_plain_form = '<form action="/search"><input type="text"></form>'
    assert detect_login_forms(html_login_form) is True
    assert detect_login_forms(html_action_login) is True
    assert detect_login_forms(html_plain_form) is False


def test_analyze_html_content():
    phishing_page = """
    <html>
      <head><title>Verify Your PayPal Account</title></head>
      <body>
        <h1>Security Alert</h1>
        <form action="/login">
          <input type="text" name="email">
          <input type="password" name="password">
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """
    analysis = analyze_html_content(phishing_page, target_brand="paypal")
    assert analysis.has_password_input is True
    assert analysis.has_login_form is True
    assert analysis.page_title == "Verify Your PayPal Account"
    assert "password" in analysis.matched_suspicious_keywords
    assert "brand:paypal" in analysis.matched_suspicious_keywords
    assert analysis.heuristic_risk_score >= 0.70


@pytest.mark.asyncio
async def test_domain_verifier_live_host(unused_tcp_port):
    async def handler(request):
        page = """
        <html>
          <head><title>Account Verification</title></head>
          <body>
            <form><input type="password" name="secret"></form>
          </body>
        </html>
        """
        return web.Response(text=page, content_type="text/html")

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()

    try:
        verifier = DomainVerifier(timeout_seconds=2.0)
        fake_domain = f"127.0.0.1:{unused_tcp_port}"

        result = await verifier.verify_domain(
            domain=fake_domain,
            target_brand="paypal",
            issuer="Let's Encrypt",
            not_before=time.time() - 1800,
        )

        assert result.is_reachable is True
        assert result.status_code == 200
        assert result.certificate.is_free_automated_ca is True
        assert result.certificate.is_newly_issued is True
        assert result.content.has_password_input is True
        assert result.confidence_multiplier > 1.20
        assert "password_input_detected" in result.risk_factors
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_domain_verifier_unreachable_host():
    verifier = DomainVerifier(timeout_seconds=0.5)
    result = await verifier.verify_domain(
        domain="127.0.0.1:59999",
        target_brand="paypal",
        issuer="DigiCert",
    )
    assert result.is_reachable is False
    assert result.status_code is None
    assert result.content.has_password_input is False
