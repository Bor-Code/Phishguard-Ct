import time
from typing import Optional
from phishguard.verification.models import CertificateMetadata

FREE_AUTOMATED_CA_KEYWORDS = (
    "let's encrypt",
    "letsencrypt",
    "zerossl",
    "cpanel",
    "cloudflare",
    "google trust services",
    "buypass",
)


def calculate_cert_age_hours(
    not_before: Optional[float], current_timestamp: Optional[float] = None
) -> Optional[float]:
    if not_before is None:
        return None
    reference_time = (
        current_timestamp if current_timestamp is not None else time.time()
    )
    delta_seconds = reference_time - not_before
    return max(0.0, round(delta_seconds / 3600.0, 2))


def is_free_automated_ca(issuer: Optional[str]) -> bool:
    if not issuer:
        return False
    normalized = issuer.lower()
    return any(keyword in normalized for keyword in FREE_AUTOMATED_CA_KEYWORDS)


def analyze_certificate(
    issuer: Optional[str],
    not_before: Optional[float],
    not_after: Optional[float],
    current_timestamp: Optional[float] = None,
    new_cert_threshold_hours: float = 72.0,
) -> CertificateMetadata:
    age_hours = calculate_cert_age_hours(not_before, current_timestamp)
    is_new = age_hours is not None and age_hours <= new_cert_threshold_hours
    is_free = is_free_automated_ca(issuer)

    return CertificateMetadata(
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        age_hours=age_hours,
        is_newly_issued=is_new,
        is_free_automated_ca=is_free,
    )
