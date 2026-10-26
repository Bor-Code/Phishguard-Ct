from phishguard.scoring import (
    ScoringEngine,
    extract_domain_tokens,
    has_homoglyphs,
    homoglyph_similarity,
    key_distance,
    keyboard_distance,
    keyboard_similarity,
    levenshtein_distance,
    levenshtein_similarity,
    normalize_homoglyphs,
)


def test_levenshtein_distance_exact():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_similarity("paypal", "paypal") == 1.0


def test_levenshtein_distance_single_edit():
    assert levenshtein_distance("paypa", "paypal") == 1
    assert levenshtein_distance("paypall", "paypal") == 1
    assert levenshtein_distance("paypxl", "paypal") == 1
    similarity = levenshtein_similarity("paypxl", "paypal")
    assert round(similarity, 2) == 0.83


def test_levenshtein_distance_empty():
    assert levenshtein_distance("", "test") == 4
    assert levenshtein_distance("test", "") == 4
    assert levenshtein_similarity("", "") == 1.0


def test_keyboard_key_distance_adjacency():
    assert key_distance("g", "g") == 0.0
    adjacent_cost = key_distance("o", "p")
    distant_cost = key_distance("o", "z")
    assert adjacent_cost < distant_cost
    assert adjacent_cost == 0.4
    assert distant_cost == 1.0


def test_keyboard_similarity_adjacent_typo():
    adjacent_typo = keyboard_similarity("paypal", "payoal")
    distant_typo = keyboard_similarity("paypal", "payzal")
    assert adjacent_typo > distant_typo


def test_homoglyph_normalization_cyrillic():
    cyrillic_google = "g\u043e\u043egle"
    assert has_homoglyphs(cyrillic_google) is True
    assert normalize_homoglyphs(cyrillic_google) == "google"
    assert homoglyph_similarity(cyrillic_google, "google") == 1.0


def test_homoglyph_normalization_greek():
    greek_paypal = "p\u03b1ypal"
    assert has_homoglyphs(greek_paypal) is True
    assert normalize_homoglyphs(greek_paypal) == "paypal"
    assert homoglyph_similarity(greek_paypal, "paypal") == 1.0


def test_homoglyph_normalization_digits():
    digit_brand = "paypa1"
    assert normalize_homoglyphs(digit_brand) == "paypal"
    assert homoglyph_similarity(digit_brand, "paypal") == 1.0


def test_extract_domain_tokens():
    tokens = extract_domain_tokens("login-verify.paypal-security.com")
    assert "paypal" in tokens
    assert "security" in tokens
    assert "login" in tokens
    assert "verify" in tokens
    assert "paypal-security" in tokens


def test_scoring_engine_homoglyph_detection():
    engine = ScoringEngine(suspect_threshold=0.75)
    cyrillic_domain = "g\u043e\u043egle-login.com"
    result = engine.score_domain_against_brand(cyrillic_domain, "google")
    assert result.composite_score >= 0.75
    assert result.is_phishing_suspect is True


def test_scoring_engine_keyboard_typo_detection():
    engine = ScoringEngine(suspect_threshold=0.75)
    result = engine.score_domain_against_brand("payoal.com", "paypal")
    assert result.composite_score >= 0.75
    assert result.is_phishing_suspect is True


def test_scoring_engine_subdomain_affix_detection():
    engine = ScoringEngine(suspect_threshold=0.75)
    result = engine.score_domain_against_brand("paypal-security-update.com", "paypal")
    assert result.is_phishing_suspect is True
    assert result.signals.subdomain_or_affix >= 0.85


def test_scoring_engine_benign_domain():
    engine = ScoringEngine(suspect_threshold=0.75)
    result = engine.score_domain_against_brand("wikipedia.org", "paypal")
    assert result.composite_score < 0.50
    assert result.is_phishing_suspect is False


def test_scoring_engine_multi_brand_selection():
    engine = ScoringEngine(suspect_threshold=0.75)
    brands = ["google", "microsoft", "paypal"]
    result = engine.score_domain("paypa1-secure-center.com", brands)
    assert result is not None
    assert result.target_brand == "paypal"
    assert result.is_phishing_suspect is True
