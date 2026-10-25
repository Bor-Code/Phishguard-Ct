import argparse
import asyncio
import logging
import signal
import sys
from typing import Optional
from phishguard.ingestion.client import CertstreamClient

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("phishguard.ingestion.runner")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phishguard.ingestion.runner",
        description="Stream live Certificate Transparency domains from Certstream",
    )
    parser.add_argument(
        "--url",
        default="wss://api.certstream.dev/domains-only",
        help="Certstream websocket server URL",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum events to display before terminating (0 for unlimited)",
    )
    return parser.parse_args()


async def stream_events(url: str, limit: int = 0) -> None:
    queue = asyncio.Queue()
    client = CertstreamClient(url=url, queue=queue)
    await client.start()

    stop_event = asyncio.Event()

    def signal_handler() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except (NotImplementedError, AttributeError):
            pass

    count = 0
    try:
        while not stop_event.is_set():
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
                count += 1
                issuer = event.issuer or "unknown_issuer"
                for domain in event.domains:
                    print(f"[{count}] domain={domain} issuer={issuer}")
                queue.task_done()
                if limit > 0 and count >= limit:
                    break
            except asyncio.TimeoutError:
                continue
    finally:
        await client.stop()


def main() -> None:
    args = parse_arguments()
    try:
        asyncio.run(stream_events(url=args.url, limit=args.limit))
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()
