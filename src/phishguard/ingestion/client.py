import asyncio
import logging
from typing import Optional
import websockets
from phishguard.ingestion.models import CertificateEvent
from phishguard.ingestion.parser import parse_certstream_message

logger = logging.getLogger(__name__)


class CertstreamClient:
    def __init__(
        self,
        url: str = "wss://api.certstream.dev/domains-only",
        queue: Optional[asyncio.Queue] = None,
        reconnect_delay: float = 3.0,
        max_reconnect_delay: float = 60.0,
    ) -> None:
        self.url = url
        self.queue = queue if queue is not None else asyncio.Queue()
        self.reconnect_delay = reconnect_delay
        self.max_reconnect_delay = max_reconnect_delay
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    async def _run_loop(self) -> None:
        current_delay = self.reconnect_delay
        while self._running:
            try:
                logger.info("Connecting to Certstream endpoint: %s", self.url)
                async with websockets.connect(
                    self.url,
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=5,
                ) as websocket:
                    logger.info("Connected to Certstream endpoint")
                    current_delay = self.reconnect_delay
                    await self._consume_websocket(websocket)
            except asyncio.CancelledError:
                break
            except Exception as error:
                if not self._running:
                    break
                logger.warning(
                    "Certstream connection dropped: %s. Reconnecting in %.1fs",
                    error,
                    current_delay,
                )
                await asyncio.sleep(current_delay)
                current_delay = min(current_delay * 2, self.max_reconnect_delay)

    async def _consume_websocket(self, websocket: websockets.WebSocketClientProtocol) -> None:
        async for message in websocket:
            if not self._running:
                break
            if isinstance(message, bytes):
                message = message.decode("utf-8", errors="replace")
            event = parse_certstream_message(message)
            if event is not None:
                await self.queue.put(event)
