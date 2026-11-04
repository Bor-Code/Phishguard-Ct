from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class FlaggedRecord:
    domain: str
    target_brand: str
    matched_term: str
    composite_score: float
    score_levenshtein: float
    score_keyboard: float
    score_homoglyph: float
    score_affix: float
    is_live: bool = False
    http_status: Optional[int] = None
    final_url: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_age_hours: Optional[float] = None
    is_free_ca: bool = False
    has_password_input: bool = False
    has_login_form: bool = False
    page_title: Optional[str] = None
    confidence_multiplier: float = 1.0
    final_confidence_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    status: str = "flagged"
    id: Optional[int] = None
    detected_at: Optional[str] = None
    updated_at: Optional[str] = None
