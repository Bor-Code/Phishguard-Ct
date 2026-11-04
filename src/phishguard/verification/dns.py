import asyncio
import socket
from typing import List, Set


def _extract_host(domain: str) -> str:
    cleaned = domain.strip().lower()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    cleaned = cleaned.split("/", 1)[0]
    cleaned = cleaned.split(":", 1)[0]
    return cleaned


def resolve_domain_ips_sync(domain: str) -> List[str]:
    host = _extract_host(domain)
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []

    ips: List[str] = []
    seen: Set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


async def resolve_domain_ips(
    domain: str,
    timeout_seconds: float = 2.0,
) -> List[str]:
    host = _extract_host(domain)
    if not host:
        return []
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP),
            timeout=timeout_seconds,
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return []

    ips: List[str] = []
    seen: Set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips
