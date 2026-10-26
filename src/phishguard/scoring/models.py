from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SignalScores:
    levenshtein: float
    keyboard: float
    homoglyph: float
    subdomain_or_affix: float


@dataclass(frozen=True)
class ScoreResult:
    domain: str
    target_brand: str
    matched_term: str
    signals: SignalScores
    composite_score: float
    is_phishing_suspect: bool
