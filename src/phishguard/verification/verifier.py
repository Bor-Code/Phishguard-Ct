from typing import Any, List, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from phishguard.verification.certificate import analyze_certificate
from phishguard.verification.dns import resolve_domain_ips
from phishguard.verification.domain_heuristics import analyze_domain_structure
from phishguard.verification.heuristics import analyze_html_content
from phishguard.verification.models import (
    CertificateMetadata,
    ContentAnalysis,
    VerificationResult,
)


class DomainVerifier:
    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 65536,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.timeout = (
            aiohttp.ClientTimeout(total=timeout_seconds, connect=timeout_seconds / 2)
            if aiohttp is not None
            else None
        )
        self.max_response_bytes = max_response_bytes
        self.headers = {"User-Agent": user_agent}

    async def _fetch_url(
        self, session: Any, url: str
    ) -> Optional[tuple[int, str, str]]:
        try:
            async with session.get(
                url,
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True,
                ssl=False,
            ) as response:
                content_chunk = await response.content.read(self.max_response_bytes)
                text = content_chunk.decode("utf-8", errors="replace")
                return response.status, str(response.url), text
        except Exception:
            return None

    def _compile_risk_factors(
        self,
        domain: str,
        cert_meta: CertificateMetadata,
        content: ContentAnalysis,
        is_live: bool,
        resolved_ips: Optional[List[str]] = None,
    ) -> List[str]:
        factors: List[str] = analyze_domain_structure(domain)
        if resolved_ips:
            factors.append("dns_record_active")
        if is_live:
            factors.append("host_reachable")
        if cert_meta.is_newly_issued:
            factors.append("newly_issued_certificate")
        if cert_meta.is_free_automated_ca:
            factors.append("free_automated_ca")
        if content.has_password_input:
            factors.append("password_input_detected")
        if content.has_login_form:
            factors.append("login_form_detected")
        if content.matched_suspicious_keywords:
            factors.append("suspicious_keywords_present")
        return factors

    def _calculate_multiplier(
        self,
        domain: str,
        cert_meta: CertificateMetadata,
        content: ContentAnalysis,
        is_live: bool,
    ) -> float:
        multiplier = 1.0
        structural_factors = analyze_domain_structure(domain)
        if "suspicious_tld" in structural_factors:
            multiplier += 0.05
        if "excessive_hyphens" in structural_factors:
            multiplier += 0.05
        if is_live:
            multiplier += 0.05
        if cert_meta.is_newly_issued:
            multiplier += 0.10
        if cert_meta.is_free_automated_ca:
            multiplier += 0.10
        if content.has_password_input:
            multiplier += 0.20
        if content.has_login_form:
            multiplier += 0.15
        return round(min(1.5, multiplier), 4)

    async def verify_domain(
        self,
        domain: str,
        target_brand: Optional[str] = None,
        issuer: Optional[str] = None,
        not_before: Optional[float] = None,
        not_after: Optional[float] = None,
    ) -> VerificationResult:
        cert_meta = analyze_certificate(
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
        )
        resolved_ips = await resolve_domain_ips(
            domain, timeout_seconds=min(2.0, self.timeout_seconds)
        )

        fetch_result = None
        if aiohttp is not None:
            async with aiohttp.ClientSession() as session:
                fetch_result = await self._fetch_url(session, f"https://{domain}")
                if fetch_result is None:
                    fetch_result = await self._fetch_url(session, f"http://{domain}")

        if fetch_result is not None:
            status_code, final_url, html_text = fetch_result
            content = analyze_html_content(html_text, target_brand=target_brand)
            is_live = True
        else:
            status_code, final_url = None, None
            content = ContentAnalysis()
            is_live = False

        factors = self._compile_risk_factors(
            domain, cert_meta, content, is_live, resolved_ips=resolved_ips
        )
        multiplier = self._calculate_multiplier(domain, cert_meta, content, is_live)

        return VerificationResult(
            domain=domain,
            is_reachable=is_live,
            status_code=status_code,
            final_url=final_url,
            certificate=cert_meta,
            content=content,
            confidence_multiplier=multiplier,
            risk_factors=factors,
            resolved_ips=resolved_ips,
        )
