import argparse
import asyncio
import json
import logging
import signal
import sys
from phishguard.api.server import run_api_server
from phishguard.config import Settings
from phishguard.evaluation.runner import main as run_evaluation
from phishguard.scoring import ScoringEngine
from phishguard.service import PhishGuardService
from phishguard.storage import DatabaseManager
from phishguard.watchlist import BrandWatchlist

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("phishguard.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Certificate Transparency Phishing Domain Detection and Monitoring",
    )
    subparsers = parser.add_subparsers(dest="command")

    monitor_parser = subparsers.add_parser(
        "monitor", help="Start real-time CT ingestion and phishing detection"
    )
    monitor_parser.add_argument("--url", help="Certstream websocket URL")
    monitor_parser.add_argument("--webhook", help="Alert webhook URL")
    monitor_parser.add_argument("--db", help="SQLite database path")
    monitor_parser.add_argument("--min-score", type=float, help="Minimum alert score threshold")
    monitor_parser.add_argument("--watchlist", help="Path to brands JSON watchlist")
    monitor_parser.add_argument("--max-events", type=int, default=0, help="Maximum events to process (0 for infinite)")

    scan_parser = subparsers.add_parser(
        "scan", help="Analyze a single domain or URL for phishing indicators"
    )
    scan_parser.add_argument("domain", help="Domain or URL to analyze")
    scan_parser.add_argument("--watchlist", default=None, help="Path to brands JSON watchlist")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Suspect score threshold")
    scan_parser.add_argument("--no-verify", action="store_true", help="Skip active HTTP/TLS verification probe")
    scan_parser.add_argument("--json", action="store_true", help="Output analysis result as JSON")
    scan_parser.add_argument("--save", action="store_true", help="Save suspect result into SQLite database")
    scan_parser.add_argument("--db", default="phishguard.db", help="SQLite database path when using --save")

    serve_parser = subparsers.add_parser(
        "serve", help="Start HTTP REST API server for healthcheck, stats, and domain queries"
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host address")
    serve_parser.add_argument("--port", type=int, default=8080, help="Bind port number")
    serve_parser.add_argument("--db", default="phishguard.db", help="SQLite database path")
    serve_parser.add_argument("--watchlist", default=None, help="Path to brands JSON watchlist")
    serve_parser.add_argument("--with-monitor", action="store_true", help="Run real-time CT monitor alongside API")

    eval_parser = subparsers.add_parser(
        "evaluate", help="Run benchmark evaluation against PhishTank and OpenPhish"
    )
    eval_parser.add_argument("--phishtank", default="data/benchmarks/phishtank_sample.json")
    eval_parser.add_argument("--openphish", default="data/benchmarks/openphish_sample.txt")
    eval_parser.add_argument("--benign", default="data/benchmarks/benign_sample.txt")
    eval_parser.add_argument("--output-dir", default="reports")
    eval_parser.add_argument("--threshold", type=float, default=0.75)

    list_parser = subparsers.add_parser(
        "list", help="List flagged phishing domains from database"
    )
    list_parser.add_argument("--db", default="phishguard.db")
    list_parser.add_argument("--min-score", type=float, default=0.0)
    list_parser.add_argument("--brand", default=None)
    list_parser.add_argument("--status", default=None)
    list_parser.add_argument("--limit", type=int, default=25)
    list_parser.add_argument("--json", action="store_true", help="Output flagged records as JSON")

    return parser


def handle_list_command(args: argparse.Namespace) -> None:
    db = DatabaseManager(database_path=args.db)
    db.initialize()
    records = db.list_flagged(
        min_score=args.min_score,
        target_brand=args.brand,
        status=args.status,
        limit=args.limit,
    )
    db.close()

    if getattr(args, "json", False):
        payload = [
            {
                "domain": r.domain,
                "target_brand": r.target_brand,
                "matched_term": r.matched_term,
                "composite_score": r.composite_score,
                "final_confidence_score": r.final_confidence_score,
                "is_live": r.is_live,
                "status": r.status,
                "risk_factors": r.risk_factors,
            }
            for r in records
        ]
        print(json.dumps(payload, indent=2))
        return

    if not records:
        print("No flagged records found matching criteria.")
        return

    print(f"{'DOMAIN':<35} {'BRAND':<12} {'SCORE':<8} {'LIVE':<6} {'STATUS':<12}")
    print("-" * 75)
    for r in records:
        live_str = "YES" if r.is_live else "NO"
        print(f"{r.domain:<35} {r.target_brand:<12} {r.final_confidence_score:<8.4f} {live_str:<6} {r.status:<12}")


async def handle_scan_command(args: argparse.Namespace) -> None:
    watchlist = (
        BrandWatchlist.from_json_file(args.watchlist)
        if args.watchlist
        else BrandWatchlist.from_defaults()
    )
    scoring_engine = ScoringEngine(suspect_threshold=args.threshold)
    database = DatabaseManager(database_path=args.db)

    service = PhishGuardService(
        watchlist=watchlist,
        scoring_engine=scoring_engine,
        database=database,
    )
    try:
        result = await service.inspect_domain(
            raw_input=args.domain,
            verify=not args.no_verify,
            persist=args.save,
        )
    finally:
        database.close()

    if args.json:
        print(json.dumps(result, indent=2))
        return

    verdict = (
        "LEGITIMATE (WHITELISTED)"
        if result["is_legitimate"]
        else ("PHISHING SUSPECT" if result["is_phishing_suspect"] else "CLEAN / LOW RISK")
    )
    print(f"Domain           : {result['domain']}")
    print(f"Verdict          : {verdict}")
    print(f"Target Brand     : {result['target_brand'] or '-'}")
    print(f"Matched Token    : {result['matched_term'] or '-'}")
    print(f"Composite Score  : {result['composite_score']:.4f}")
    print(f"Final Confidence : {result['final_confidence_score']:.4f}")
    signals = result["signals"]
    print(
        f"Signals          : lev={signals['levenshtein']:.4f} "
        f"key={signals['keyboard']:.4f} "
        f"homo={signals['homoglyph']:.4f} "
        f"affix={signals['subdomain_or_affix']:.4f}"
    )
    verification = result["verification"]
    if verification is not None:
        live_str = "YES" if verification["is_reachable"] else "NO"
        factors = ", ".join(verification["risk_factors"]) if verification["risk_factors"] else "none"
        print(f"Host Reachable   : {live_str} (status={verification['status_code']})")
        print(f"Risk Factors     : {factors}")


async def handle_serve_command(args: argparse.Namespace) -> None:
    base_settings = Settings.from_env()
    settings = Settings(
        certstream_url=base_settings.certstream_url,
        alert_webhook_url=base_settings.alert_webhook_url,
        alert_provider=base_settings.alert_provider,
        telegram_chat_id=base_settings.telegram_chat_id,
        database_path=args.db or base_settings.database_path,
        log_level=base_settings.log_level,
        min_alert_score=base_settings.min_alert_score,
        watchlist_path=args.watchlist or base_settings.watchlist_path,
        http_timeout_seconds=base_settings.http_timeout_seconds,
    )
    service = PhishGuardService(settings=settings)
    await run_api_server(
        host=args.host,
        port=args.port,
        service=service,
        with_monitor=args.with_monitor,
    )


async def run_monitor_service(settings: Settings, max_events: int = 0) -> None:
    service = PhishGuardService(settings=settings)
    stop_event = asyncio.Event()

    def signal_handler() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except (NotImplementedError, AttributeError):
            pass

    monitor_task = asyncio.create_task(service.start(max_events=max_events))
    try:
        while not stop_event.is_set() and not monitor_task.done():
            await asyncio.sleep(0.5)
    finally:
        await service.stop()
        if not monitor_task.done():
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    command = args.command or "monitor"

    if command == "evaluate":
        sys.argv = [sys.argv[0]]
        if hasattr(args, "phishtank") and args.phishtank:
            sys.argv.extend(["--phishtank", args.phishtank])
        if hasattr(args, "openphish") and args.openphish:
            sys.argv.extend(["--openphish", args.openphish])
        if hasattr(args, "benign") and args.benign:
            sys.argv.extend(["--benign", args.benign])
        if hasattr(args, "output_dir") and args.output_dir:
            sys.argv.extend(["--output-dir", args.output_dir])
        if hasattr(args, "threshold") and args.threshold:
            sys.argv.extend(["--threshold", str(args.threshold)])
        run_evaluation()
        return

    if command == "list":
        handle_list_command(args)
        return

    if command == "scan":
        asyncio.run(handle_scan_command(args))
        return

    if command == "serve":
        try:
            asyncio.run(handle_serve_command(args))
        except KeyboardInterrupt:
            logger.info("API server stopped by user.")
            sys.exit(0)
        return

    base_settings = Settings.from_env()
    certstream_url = getattr(args, "url", None) or base_settings.certstream_url
    webhook_url = getattr(args, "webhook", None) or base_settings.alert_webhook_url
    database_path = getattr(args, "db", None) or base_settings.database_path
    min_score = getattr(args, "min_score", None) or base_settings.min_alert_score
    watchlist_path = getattr(args, "watchlist", None) or base_settings.watchlist_path
    max_events = getattr(args, "max_events", 0)

    settings = Settings(
        certstream_url=certstream_url,
        alert_webhook_url=webhook_url,
        alert_provider=base_settings.alert_provider,
        telegram_chat_id=base_settings.telegram_chat_id,
        database_path=database_path,
        log_level=base_settings.log_level,
        min_alert_score=min_score,
        watchlist_path=watchlist_path,
        http_timeout_seconds=base_settings.http_timeout_seconds,
    )

    try:
        asyncio.run(run_monitor_service(settings=settings, max_events=max_events))
    except KeyboardInterrupt:
        logger.info("Monitor interrupted by user. Exiting cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()
