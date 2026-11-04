from typing import List, Set

SUSPICIOUS_TLDS: Set[str] = {
    "xyz",
    "top",
    "online",
    "site",
    "club",
    "icu",
    "vip",
    "shop",
    "click",
    "buzz",
    "live",
    "support",
    "info",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "rest",
}


def extract_tld(domain: str) -> str:
    cleaned = domain.strip().lower().split(":", 1)[0]
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) < 2:
        return ""
    return parts[-1]


def is_suspicious_tld(domain: str) -> bool:
    tld = extract_tld(domain)
    return tld in SUSPICIOUS_TLDS


def count_domain_hyphens(domain: str) -> int:
    cleaned = domain.strip().lower().split(":", 1)[0]
    parts = [p for p in cleaned.split(".") if p]
    base_labels = parts[:-1] if len(parts) > 1 else parts
    return sum(label.count("-") for label in base_labels)


def has_excessive_hyphens(domain: str, threshold: int = 2) -> bool:
    return count_domain_hyphens(domain) >= threshold


def analyze_domain_structure(domain: str) -> List[str]:
    factors: List[str] = []
    if is_suspicious_tld(domain):
        factors.append("suspicious_tld")
    if has_excessive_hyphens(domain):
        factors.append("excessive_hyphens")
    return factors
