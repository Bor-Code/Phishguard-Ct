import unicodedata
from typing import Dict
from phishguard.scoring.levenshtein import levenshtein_similarity

HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a",
    "\u03b1": "a",
    "\u00e0": "a",
    "\u00e1": "a",
    "\u00e2": "a",
    "\u00e3": "a",
    "\u00e4": "a",
    "\u00e5": "a",
    "\u0432": "b",
    "\u03b2": "b",
    "\u0441": "c",
    "\u00e7": "c",
    "\u0434": "d",
    "\u0501": "d",
    "\u0435": "e",
    "\u0454": "e",
    "\u03b5": "e",
    "\u00e8": "e",
    "\u00e9": "e",
    "\u00ea": "e",
    "\u00eb": "e",
    "\u04bb": "h",
    "\u0456": "i",
    "\u0457": "i",
    "\u03b9": "i",
    "\u00ec": "i",
    "\u00ed": "i",
    "\u00ee": "i",
    "\u00ef": "i",
    "\u0458": "j",
    "\u043a": "k",
    "\u03ba": "k",
    "\u04cf": "l",
    "\u043c": "m",
    "\u043d": "n",
    "\u043e": "o",
    "\u03bf": "o",
    "\u00f2": "o",
    "\u00f3": "o",
    "\u00f4": "o",
    "\u00f5": "o",
    "\u00f6": "o",
    "\u00f8": "o",
    "\u0440": "p",
    "\u03c1": "p",
    "\u0442": "t",
    "\u03c4": "t",
    "\u0443": "y",
    "\u03c5": "u",
    "\u00f9": "u",
    "\u00fa": "u",
    "\u00fb": "u",
    "\u00fc": "u",
    "\u0475": "v",
    "\u03bd": "v",
    "\u0445": "x",
    "\u03c7": "x",
    "\u0443": "y",
    "\u00fd": "y",
    "\u00ff": "y",
    "\u0455": "s",
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
}


def decode_punycode_label(label: str) -> str:
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return label


def decode_punycode_domain(domain: str) -> str:
    labels = domain.split(".")
    decoded_labels = [decode_punycode_label(label) for label in labels]
    return ".".join(decoded_labels)


def strip_combining_characters(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def normalize_homoglyphs(text: str) -> str:
    decoded = decode_punycode_domain(text.lower())
    unaccented = strip_combining_characters(decoded)
    normalized_chars = []
    for char in unaccented:
        replacement = HOMOGLYPH_MAP.get(char, char)
        normalized_chars.append(replacement)
    return "".join(normalized_chars)


def has_homoglyphs(raw_text: str) -> bool:
    normalized = normalize_homoglyphs(raw_text)
    return normalized != raw_text.lower()


def homoglyph_similarity(candidate_term: str, target_brand: str) -> float:
    normalized_candidate = normalize_homoglyphs(candidate_term)
    normalized_target = normalize_homoglyphs(target_brand)
    if normalized_candidate == normalized_target:
        return 1.0
    return levenshtein_similarity(normalized_candidate, normalized_target)
