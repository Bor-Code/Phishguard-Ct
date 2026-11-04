import asyncio
import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

try:
    from aiohttp import web
except ImportError:
    web = None  # type: ignore[assignment]

from phishguard import __version__
from phishguard.api.dashboard import render_dashboard_html
from phishguard.service import PhishGuardService
from phishguard.storage.models import FlaggedRecord

logger = logging.getLogger("phishguard.api")

ALLOWED_DOMAIN_STATUSES = {"flagged", "confirmed", "dismissed", "alert_sent"}


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

    def get_dashboard_html(self) -> str:
        return render_dashboard_html()

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

    def get_watchlist(self) -> Dict[str, Any]:
        brands = [
            {
                "name": b.name,
                "keywords": list(b.keywords),
                "legitimate_domains": list(b.canonical_domains),
                "similarity_threshold": self.service.settings.min_alert_score,
            }
            for b in self.service.watchlist.all_brands()
        ]
        return {"count": len(brands), "brands": brands}

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

    def update_domain_status(self, domain: str, status: str) -> Optional[Dict[str, Any]]:
        normalized_domain = domain.strip().lower()
        normalized_status = status.strip().lower()
        if normalized_status not in ALLOWED_DOMAIN_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Allowed values: {sorted(ALLOWED_DOMAIN_STATUSES)}"
            )
        updated = self.service.database.update_status(normalized_domain, normalized_status)
        if not updated:
            return None
        return self.get_domain_detail(normalized_domain)

    def export_domains(
        self,
        fmt: str = "json",
        min_score: float = 0.0,
        brand: Optional[str] = None,
        limit: int = 500,
    ) -> Tuple[str, str]:
        items = self.list_domains(min_score=min_score, brand=brand, limit=limit)
        normalized_fmt = fmt.strip().lower()
        if normalized_fmt == "csv":
            output = io.StringIO()
            fieldnames = [
                "id",
                "domain",
                "target_brand",
                "matched_term",
                "composite_score",
                "final_confidence_score",
                "is_live",
                "http_status",
                "cert_issuer",
                "status",
                "risk_factors",
                "detected_at",
            ]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for item in items:
                writer.writerow(
                    {
                        "id": item["id"],
                        "domain": item["domain"],
                        "target_brand": item["target_brand"],
                        "matched_term": item["matched_term"],
                        "composite_score": item["composite_score"],
                        "final_confidence_score": item["final_confidence_score"],
                        "is_live": item["is_live"],
                        "http_status": item["http_status"],
                        "cert_issuer": item["cert_issuer"],
                        "status": item["status"],
                        "risk_factors": ",".join(item.get("risk_factors") or []),
                        "detected_at": item["detected_at"],
                    }
                )
            return output.getvalue(), "text/csv; charset=utf-8"

        return json.dumps(items, indent=2), "application/json"

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

    async def batch_scan_domains(
        self,
        domains: List[str],
        verify: bool = False,
        save: bool = False,
    ) -> Dict[str, Any]:
        cleaned = [str(d).strip() for d in domains if str(d).strip()][:100]
        results = await self.service.batch_inspect_domains(
            domains=cleaned,
            verify=verify,
            persist=save,
        )
        suspects = sum(1 for r in results if r.get("is_phishing_suspect"))
        return {
            "total_scanned": len(results),
            "suspects_detected": suspects,
            "results": results,
        }


def create_api_app(service: Optional[PhishGuardService] = None) -> Any:
    if web is None:
        raise RuntimeError("aiohttp is required to create the HTTP API application")

    api = PhishGuardAPIServer(service=service)

    async def handle_dashboard(request: web.Request) -> web.Response:
        return web.Response(text=api.get_dashboard_html(), content_type="text/html")

    async def handle_health(request: web.Request) -> web.Response:
        return web.json_response(api.get_health())

    async def handle_stats(request: web.Request) -> web.Response:
        return web.json_response(api.get_stats())

    async def handle_watchlist(request: web.Request) -> web.Response:
        return web.json_response(api.get_watchlist())

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

    async def handle_export(request: web.Request) -> web.Response:
        fmt = request.query.get("format", "json")
        brand = request.query.get("brand")
        try:
            min_score = float(request.query.get("min_score", "0.0"))
        except ValueError:
            min_score = 0.0
        payload, content_type = api.export_domains(
            fmt=fmt, min_score=min_score, brand=brand
        )
        ext = "csv" if fmt.strip().lower() == "csv" else "json"
        return web.Response(
            text=payload,
            content_type=content_type.split(";")[0],
            headers={"Content-Disposition": f'attachment; filename="phishguard-export.{ext}"'},
        )

    async def handle_get_domain(request: web.Request) -> web.Response:
        domain = request.match_info.get("domain", "")
        detail = api.get_domain_detail(domain)
        if detail is None:
            return web.json_response({"error": "Domain not found"}, status=404)
        return web.json_response(detail)

    async def handle_update_domain_status(request: web.Request) -> web.Response:
        domain = request.match_info.get("domain", "")
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        new_status = str(body.get("status", "")).strip()
        if not new_status:
            return web.json_response({"error": "'status' field is required"}, status=400)

        try:
            updated = api.update_domain_status(domain=domain, status=new_status)
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)

        if updated is None:
            return web.json_response({"error": "Domain not found"}, status=404)
        return web.json_response(updated)

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

    async def handle_batch_scan(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        raw_domains = body.get("domains")
        if not isinstance(raw_domains, list) or not raw_domains:
            return web.json_response(
                {"error": "'domains' must be a non-empty list"}, status=400
            )
        verify = bool(body.get("verify", False))
        save = bool(body.get("save", False))
        result = await api.batch_scan_domains(
            domains=raw_domains, verify=verify, save=save
        )
        return web.json_response(result)

    app = web.Application()
    app["phishguard_api"] = api
    app.router.add_get("/", handle_dashboard)
    app.router.add_get("/dashboard", handle_dashboard)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/stats", handle_stats)
    app.router.add_get("/watchlist", handle_watchlist)
    app.router.add_get("/export", handle_export)
    app.router.add_get("/domains", handle_list_domains)
    app.router.add_get("/domains/{domain}", handle_get_domain)
    app.router.add_patch("/domains/{domain}", handle_update_domain_status)
    app.router.add_post("/scan", handle_scan)
    app.router.add_post("/batch-scan", handle_batch_scan)
    return app


def _run_stdlib_server(host: str, port: int, api: PhishGuardAPIServer) -> None:
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, payload: Any, status: int = 200) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)
            if path in ("/", "/dashboard"):
                html = api.get_dashboard_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            elif path == "/health":
                self._send_json(api.get_health())
            elif path == "/stats":
                self._send_json(api.get_stats())
            elif path == "/watchlist":
                self._send_json(api.get_watchlist())
            elif path == "/export":
                fmt = qs.get("format", ["json"])[0]
                brand = qs.get("brand", [None])[0]
                payload, ctype = api.export_domains(fmt=fmt, brand=brand)
                raw = payload.encode("utf-8")
                ext = "csv" if fmt.strip().lower() == "csv" else "json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header(
                    "Content-Disposition", f'attachment; filename="phishguard-export.{ext}"'
                )
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif path == "/domains":
                brand = qs.get("brand", [None])[0]
                status = qs.get("status", [None])[0]
                min_score = float(qs.get("min_score", ["0.0"])[0])
                items = api.list_domains(min_score=min_score, brand=brand, status=status)
                self._send_json({"count": len(items), "items": items})
            elif path.startswith("/domains/"):
                domain = unquote(path[len("/domains/") :])
                detail = api.get_domain_detail(domain)
                if detail is None:
                    self._send_json({"error": "Domain not found"}, status=404)
                else:
                    self._send_json(detail)
            else:
                self._send_json({"error": "Not found"}, status=404)

        def _read_json_body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw) if raw else {}

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            body = self._read_json_body()
            if parsed.path == "/scan":
                domain = str(body.get("domain", "")).strip()
                if not domain:
                    self._send_json({"error": "'domain' field is required"}, status=400)
                    return
                res = asyncio.run(
                    api.scan_domain(
                        domain=domain,
                        verify=bool(body.get("verify", False)),
                        save=bool(body.get("save", False)),
                    )
                )
                self._send_json(res)
            elif parsed.path == "/batch-scan":
                domains = body.get("domains") or []
                res = asyncio.run(
                    api.batch_scan_domains(
                        domains=domains,
                        verify=bool(body.get("verify", False)),
                        save=bool(body.get("save", False)),
                    )
                )
                self._send_json(res)
            else:
                self._send_json({"error": "Not found"}, status=404)

        def do_PATCH(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path.startswith("/domains/"):
                domain = unquote(parsed.path[len("/domains/") :])
                body = self._read_json_body()
                try:
                    updated = api.update_domain_status(domain, str(body.get("status", "")))
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                    return
                if updated is None:
                    self._send_json({"error": "Domain not found"}, status=404)
                else:
                    self._send_json(updated)
            else:
                self._send_json({"error": "Not found"}, status=404)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    logger.info("PhishGuard Stdlib HTTP GUI listening on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


async def run_api_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    service: Optional[PhishGuardService] = None,
    with_monitor: bool = False,
) -> None:
    svc = service or PhishGuardService()
    if web is None:
        api = PhishGuardAPIServer(service=svc)
        await asyncio.to_thread(_run_stdlib_server, host, port, api)
        svc.database.close()
        return

    app = create_api_app(service=svc)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("PhishGuard REST API & Dashboard listening on http://%s:%d", host, port)

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
