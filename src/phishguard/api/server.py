import asyncio
import logging
from typing import Any, Dict, List, Optional

try:
    from aiohttp import web
except ImportError:
    web = None  # type: ignore[assignment]

from phishguard import __version__
from phishguard.service import PhishGuardService
from phishguard.storage.models import FlaggedRecord

logger = logging.getLogger("phishguard.api")


def serialize_record(record: FlaggedRecord) -> Dict[str, Any]:
    return {
        "id": record.id,
        "domain": record.domain,
        "target_brand": record.target_brand,
        "matched_term": record.matched_term,
        "composite_score": record.composite_score,
        "signals": {
            "levenshtein": record.score_levenshtein,
            "keyboard": record.score_keyboard,
            "homoglyph": record.score_homoglyph,
            "subdomain_or_affix": record.score_affix,
        },
        "is_live": record.is_live,
        "http_status": record.http_status,
        "final_url": record.final_url,
        "cert_issuer": record.cert_issuer,
        "cert_age_hours": record.cert_age_hours,
        "is_free_ca": record.is_free_ca,
        "has_password_input": record.has_password_input,
        "has_login_form": record.has_login_form,
        "page_title": record.page_title,
        "confidence_multiplier": record.confidence_multiplier,
        "final_confidence_score": record.final_confidence_score,
        "risk_factors": record.risk_factors,
        "status": record.status,
        "detected_at": record.detected_at,
        "updated_at": record.updated_at,
    }


class PhishGuardAPIServer:
    def __init__(self, service: Optional[PhishGuardService] = None) -> None:
        self.service = service or PhishGuardService()
        self.service.database.initialize()

    def get_health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "service": "phishguard-ct",
            "version": __version__,
        }

    def get_stats(self) -> Dict[str, Any]:
        summary = self.service.database.get_summary_stats()
        summary["watchlist_brands_count"] = len(self.service.watchlist.all_brands())
        return summary

    def list_domains(
        self,
        min_score: float = 0.0,
        brand: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        records = self.service.database.list_flagged(
            min_score=min_score,
            target_brand=brand,
            status=status,
            limit=limit,
        )
        return [serialize_record(r) for r in records]

    def get_domain_detail(self, domain: str) -> Optional[Dict[str, Any]]:
        record = self.service.database.get_domain(domain.strip().lower())
        if record is None:
            return None
        return serialize_record(record)

    async def scan_domain(
        self,
        domain: str,
        verify: bool = False,
        save: bool = False,
    ) -> Dict[str, Any]:
        return await self.service.inspect_domain(
            raw_input=domain,
            verify=verify,
            persist=save,
        )


def create_api_app(service: Optional[PhishGuardService] = None) -> Any:
    if web is None:
        raise RuntimeError("aiohttp is required to create the HTTP API application")

    api = PhishGuardAPIServer(service=service)

    async def handle_health(request: web.Request) -> web.Response:
        return web.json_response(api.get_health())

    async def handle_stats(request: web.Request) -> web.Response:
        return web.json_response(api.get_stats())

    async def handle_list_domains(request: web.Request) -> web.Response:
        try:
            min_score = float(request.query.get("min_score", "0.0"))
        except ValueError:
            min_score = 0.0
        try:
            limit = int(request.query.get("limit", "50"))
        except ValueError:
            limit = 50

        brand = request.query.get("brand")
        status = request.query.get("status")
        items = api.list_domains(
            min_score=min_score,
            brand=brand,
            status=status,
            limit=max(1, min(limit, 500)),
        )
        return web.json_response({"count": len(items), "items": items})

    async def handle_get_domain(request: web.Request) -> web.Response:
        domain = request.match_info.get("domain", "")
        detail = api.get_domain_detail(domain)
        if detail is None:
            return web.json_response({"error": "Domain not found"}, status=404)
        return web.json_response(detail)

    async def handle_scan(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        domain = str(body.get("domain", "")).strip()
        if not domain:
            return web.json_response({"error": "'domain' field is required"}, status=400)

        verify = bool(body.get("verify", False))
        save = bool(body.get("save", False))
        result = await api.scan_domain(domain=domain, verify=verify, save=save)
        return web.json_response(result)

    app = web.Application()
    app["phishguard_api"] = api
    app.router.add_get("/health", handle_health)
    app.router.add_get("/stats", handle_stats)
    app.router.add_get("/domains", handle_list_domains)
    app.router.add_get("/domains/{domain}", handle_get_domain)
    app.router.add_post("/scan", handle_scan)
    return app


async def run_api_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    service: Optional[PhishGuardService] = None,
    with_monitor: bool = False,
) -> None:
    if web is None:
        raise RuntimeError("aiohttp is required to run the HTTP API server")

    svc = service or PhishGuardService()
    app = create_api_app(service=svc)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("PhishGuard REST API listening on http://%s:%d", host, port)

    monitor_task: Optional[asyncio.Task] = None
    if with_monitor:
        monitor_task = asyncio.create_task(svc.start())

    try:
        while True:
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        pass
    finally:
        if monitor_task is not None:
            await svc.stop()
            if not monitor_task.done():
                monitor_task.cancel()
        await runner.cleanup()
        svc.database.close()
