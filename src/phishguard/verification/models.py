from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class CertificateMetadata:
    issuer: Optional[str] = None
    not_before: Optional[float] = None
    not_after: Optional[float] = None
    age_hours: Optional[float] = None
    is_newly_issued: bool = False
    is_free_automated_ca: bool = False


@dataclass(frozen=True)
class ContentAnalysis:
    has_password_input: bool = False
    has_login_form: bool = False
    page_title: Optional[str] = None
    matched_suspicious_keywords: List[str] = field(default_factory=list)
    heuristic_risk_score: float = 0.0


@dataclass(frozen=True)
class VerificationResult:
    domain: str
    is_reachable: bool
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    certificate: CertificateMetadata = field(default_factory=CertificateMetadata)
    content: ContentAnalysis = field(default_factory=ContentAnalysis)
    confidence_multiplier: float = 1.0
    risk_factors: List[str] = field(default_factory=list)
