import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from phishguard.scoring.homoglyph import homoglyph_similarity, normalize_homoglyphs
from phishguard.scoring.keyboard import keyboard_similarity
from phishguard.scoring.levenshtein import levenshtein_similarity
from phishguard.scoring.models import ScoreResult, SignalScores


def extract_domain_tokens(domain: str) -> List[str]:
    cleaned = domain.strip().lower()
    labels = cleaned.split(".")
    if not labels:
        return []

    tokens: Set[str] = set()
    base_labels = labels[:-1] if len(labels) > 1 else labels
    for label in base_labels:
        if label:
            tokens.add(label)
            subparts = re.split(r"[-_]", label)
            for part in subparts:
                if part:
                    tokens.add(part)

    if len(base_labels) >= 1:
        tokens.add("".join(base_labels))
    return sorted(tokens, key=lambda token: len(token), reverse=True)


def calculate_affix_similarity(token: str, brand: str) -> float:
    normalized_token = normalize_homoglyphs(token)
    normalized_brand = normalize_homoglyphs(brand)
    if normalized_token == normalized_brand:
        return 1.0
    if normalized_token.startswith(normalized_brand) or normalized_token.endswith(normalized_brand):
        return 0.85
    if normalized_brand in normalized_token:
        return 0.75
    return 0.0


class ScoringEngine:
    def __init__(
        self,
        weight_levenshtein: float = 0.35,
        weight_keyboard: float = 0.25,
        weight_homoglyph: float = 0.25,
        weight_affix: float = 0.15,
        suspect_threshold: float = 0.75,
    ) -> None:
        self.weight_levenshtein = weight_levenshtein
        self.weight_keyboard = weight_keyboard
        self.weight_homoglyph = weight_homoglyph
        self.weight_affix = weight_affix
        self.suspect_threshold = suspect_threshold
        self.total_weight = (
            self.weight_levenshtein
            + self.weight_keyboard
            + self.weight_homoglyph
            + self.weight_affix
        )

    def compute_composite_score(self, signals: SignalScores) -> float:
        if signals.subdomain_or_affix > 0.0:
            active_weight = (
                self.weight_levenshtein
                + self.weight_keyboard
                + self.weight_homoglyph
                + self.weight_affix
            )
            weighted_sum = (
                signals.levenshtein * self.weight_levenshtein
                + signals.keyboard * self.weight_keyboard
                + signals.homoglyph * self.weight_homoglyph
                + signals.subdomain_or_affix * self.weight_affix
            )
        else:
            active_weight = (
                self.weight_levenshtein
                + self.weight_keyboard
                + self.weight_homoglyph
            )
            weighted_sum = (
                signals.levenshtein * self.weight_levenshtein
                + signals.keyboard * self.weight_keyboard
                + signals.homoglyph * self.weight_homoglyph
            )

        if active_weight <= 0:
            return 0.0
        normalized = weighted_sum / active_weight
        return max(0.0, min(1.0, round(normalized, 4)))

    def evaluate_token(self, token: str, brand: str) -> Tuple[SignalScores, float]:
        lev_score = levenshtein_similarity(token, brand)
        key_score = keyboard_similarity(token, brand)
        homo_score = homoglyph_similarity(token, brand)
        affix_score = calculate_affix_similarity(token, brand)

        signals = SignalScores(
            levenshtein=round(lev_score, 4),
            keyboard=round(key_score, 4),
            homoglyph=round(homo_score, 4),
            subdomain_or_affix=round(affix_score, 4),
        )
        composite = self.compute_composite_score(signals)
        return signals, composite

    def score_domain_against_brand(self, domain: str, brand: str) -> ScoreResult:
        tokens = extract_domain_tokens(domain)
        if not tokens:
            empty_signals = SignalScores(0.0, 0.0, 0.0, 0.0)
            return ScoreResult(
                domain=domain,
                target_brand=brand,
                matched_term="",
                signals=empty_signals,
                composite_score=0.0,
                is_phishing_suspect=False,
            )

        best_term = tokens[0]
        best_signals = SignalScores(0.0, 0.0, 0.0, 0.0)
        best_composite = 0.0

        for token in tokens:
            signals, composite = self.evaluate_token(token, brand)
            if composite > best_composite:
                best_composite = composite
                best_signals = signals
                best_term = token

        is_suspect = best_composite >= self.suspect_threshold
        return ScoreResult(
            domain=domain,
            target_brand=brand,
            matched_term=best_term,
            signals=best_signals,
            composite_score=best_composite,
            is_phishing_suspect=is_suspect,
        )

    def score_domain(
        self, domain: str, target_brands: Iterable[str]
    ) -> Optional[ScoreResult]:
        best_result: Optional[ScoreResult] = None
        for brand in target_brands:
            result = self.score_domain_against_brand(domain, brand)
            if best_result is None or result.composite_score > best_result.composite_score:
                best_result = result

        return best_result
