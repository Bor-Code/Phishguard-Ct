import aiohttp
from aiohttp import web
import pytest
from phishguard.api import PhishGuardAPIServer, create_api_app
from phishguard.service import PhishGuardService
from phishguard.storage import DatabaseManager, FlaggedRecord
from phishguard.verification import DomainVerifier, VerificationResult


class MockAPIVerifier(DomainVerifier):
    async def verify_domain(
        self,
        domain: str,
        target_brand=None,
        issuer=None,
        not_before=None,
        not_after=None,
    ) -> VerificationResult:
        return VerificationResult(
            domain=domain,
            is_reachable=True,
            status_code=200,
            final_url=f"https://{domain}/login",
            confidence_multiplier=1.2,
            risk_factors=["password_input_detected"],
        )


def build_test_service() -> PhishGuardService:
    db = DatabaseManager(database_path=":memory:")
    db.initialize()
    db.record_detection(
        FlaggedRecord(
            domain="paypa1-security.com",
            target_brand="paypal",
            matched_term="paypa1",
            composite_score=0.90,
            score_levenshtein=0.83,
            score_keyboard=0.92,
            score_homoglyph=1.0,
            score_affix=0.85,
            is_live=True,
            http_status=200,
            final_confidence_score=0.98,
            risk_factors=["password_input_detected"],
            status="alert_sent",
        )
    )
    return PhishGuardService(
        database=db,
        verifier=MockAPIVerifier(),
    )


@pytest.mark.asyncio
async def test_api_server_methods():
    service = build_test_service()
    api = PhishGuardAPIServer(service=service)

    health = api.get_health()
    assert health["status"] == "ok"
    assert health["service"] == "phishguard-ct"

    html = api.get_dashboard_html()
    assert "PhishGuard-CT SOC Console" in html
    assert "On-Demand Domain Analyzer" in html
    assert "Triage Status Breakdown" in html
    assert "Bulk Domain Threat Analyzer" in html

    stats = api.get_stats()
    assert stats["total_flagged"] == 1
    assert stats["live_domains"] == 1
    assert stats["alerts_sent"] == 1
    assert stats["by_brand"]["paypal"] == 1
    assert stats["by_status"]["alert_sent"] == 1
    assert stats["severity_buckets"]["critical"] == 1
    assert "levenshtein" in stats["signal_averages"]
    assert stats["watchlist_brands_count"] >= 10

    watchlist = api.get_watchlist()
    assert watchlist["count"] >= 10
    assert any(b["name"] == "paypal" for b in watchlist["brands"])

    csv_payload, csv_type = api.export_domains(fmt="csv")
    assert "text/csv" in csv_type
    assert "paypa1-security.com" in csv_payload

    domains = api.list_domains(brand="paypal")
    assert len(domains) == 1
    assert domains[0]["domain"] == "paypa1-security.com"

    detail = api.get_domain_detail("paypa1-security.com")
    assert detail is not None
    assert detail["target_brand"] == "paypal"
    assert api.get_domain_detail("unknown-domain.org") is None

    updated = api.update_domain_status("paypa1-security.com", "confirmed")
    assert updated is not None
    assert updated["status"] == "confirmed"
    assert api.update_domain_status("unknown-domain.org", "dismissed") is None

    with pytest.raises(ValueError):
        api.update_domain_status("paypa1-security.com", "invalid_status")

    scan_result = await api.scan_domain("g00gle-verify.xyz", verify=True, save=True)
    assert scan_result["is_phishing_suspect"] is True
    assert scan_result["target_brand"] == "google"
    assert api.get_stats()["total_flagged"] == 2

    batch_result = await api.batch_scan_domains(
        ["micr0soft-login.top", "example.org"], verify=False, save=True
    )
    assert batch_result["total_scanned"] == 2
    assert batch_result["suspects_detected"] >= 1
    service.database.close()


@pytest.mark.asyncio
async def test_api_http_endpoints(unused_tcp_port):
    service = build_test_service()
    app = create_api_app(service=service)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()

    base_url = f"http://127.0.0.1:{unused_tcp_port}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base_url}/") as resp:
                assert resp.status == 200
                text = await resp.text()
                assert "PhishGuard-CT SOC Console" in text

            async with session.get(f"{base_url}/health") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["status"] == "ok"

            async with session.get(f"{base_url}/stats") as resp:
                assert resp.status == 200
                stats = await resp.json()
                assert stats["total_flagged"] == 1
                assert "severity_buckets" in stats

            async with session.get(f"{base_url}/watchlist") as resp:
                assert resp.status == 200
                wl = await resp.json()
                assert wl["count"] >= 10

            async with session.get(f"{base_url}/export?format=csv") as resp:
                assert resp.status == 200
                csv_text = await resp.text()
                assert "paypa1-security.com" in csv_text

            async with session.get(f"{base_url}/domains?brand=paypal") as resp:
                assert resp.status == 200
                listing = await resp.json()
                assert listing["count"] == 1
                assert listing["items"][0]["domain"] == "paypa1-security.com"

            async with session.get(f"{base_url}/domains/paypa1-security.com") as resp:
                assert resp.status == 200
                detail = await resp.json()
                assert detail["domain"] == "paypa1-security.com"

            async with session.get(f"{base_url}/domains/missing.com") as resp:
                assert resp.status == 404

            async with session.patch(
                f"{base_url}/domains/paypa1-security.com",
                json={"status": "confirmed"},
            ) as resp:
                assert resp.status == 200
                patched = await resp.json()
                assert patched["status"] == "confirmed"

            async with session.patch(
                f"{base_url}/domains/paypa1-security.com",
                json={"status": "not_allowed"},
            ) as resp:
                assert resp.status == 400

            async with session.patch(
                f"{base_url}/domains/missing.com",
                json={"status": "dismissed"},
            ) as resp:
                assert resp.status == 404

            async with session.post(
                f"{base_url}/scan",
                json={"domain": "faceb00k-security-notice.info", "verify": False, "save": True},
            ) as resp:
                assert resp.status == 200
                scan_data = await resp.json()
                assert scan_data["is_phishing_suspect"] is True
                assert scan_data["target_brand"] == "meta"

            async with session.post(
                f"{base_url}/batch-scan",
                json={"domains": ["paypa1-help.xyz", "google.com"], "verify": False, "save": False},
            ) as resp:
                assert resp.status == 200
                batch_data = await resp.json()
                assert batch_data["total_scanned"] == 2
                assert batch_data["suspects_detected"] == 1
    finally:
        await runner.cleanup()
        service.database.close()
