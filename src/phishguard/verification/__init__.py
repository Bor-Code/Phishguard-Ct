from phishguard.verification.certificate import (
    analyze_certificate,
    calculate_cert_age_hours,
    is_free_automated_ca,
)
from phishguard.verification.dns import (
    resolve_domain_ips,
    resolve_domain_ips_sync,
)
from phishguard.verification.domain_heuristics import (
    SUSPICIOUS_TLDS,
    analyze_domain_structure,
    count_domain_hyphens,
    extract_tld,
    has_excessive_hyphens,
    is_suspicious_tld,
)
from phishguard.verification.heuristics import (
    analyze_html_content,
    detect_login_forms,
    detect_password_inputs,
    extract_page_title,
)
from phishguard.verification.models import (
    CertificateMetadata,
    ContentAnalysis,
    VerificationResult,
)
from phishguard.verification.verifier import DomainVerifier

__all__ = [
    "DomainVerifier",
    "VerificationResult",
    "CertificateMetadata",
    "ContentAnalysis",
    "SUSPICIOUS_TLDS",
    "analyze_certificate",
    "calculate_cert_age_hours",
    "is_free_automated_ca",
    "resolve_domain_ips",
    "resolve_domain_ips_sync",
    "analyze_domain_structure",
    "count_domain_hyphens",
    "extract_tld",
    "has_excessive_hyphens",
    "is_suspicious_tld",
    "analyze_html_content",
    "detect_password_inputs",
    "detect_login_forms",
    "extract_page_title",
]
