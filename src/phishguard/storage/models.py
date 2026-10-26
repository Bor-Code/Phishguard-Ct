from dataclasses import dataclass
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
    is_live: bool
    http_status: Optional[int]
    final_url: Optional[str]
    cert_issuer: Optional[str]
    cert_age_hours: Optional[float]
    is_free_ca: bool
    has_password_input: bool
    has_login_form: bool
    page_title: Optional[str]
    confidence_multiplier: float
    final_confidence_score: float
    risk_factors: List[str]
    status: str = "flagged"
    id: Optional[int] = None
    detected_at: Optional[str] = None
    updated_at: Optional[str] = None
