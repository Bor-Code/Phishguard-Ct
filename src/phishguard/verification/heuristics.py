import html
import re
from typing import List, Optional
from phishguard.verification.models import ContentAnalysis

TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
PASSWORD_INPUT_PATTERN = re.compile(
    r"""<input[^>]+(?:type\s*=\s*['"]password['"]|type\s*=\s*password)[^>]*>""",
    re.IGNORECASE,
)
FORM_PATTERN = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)

SUSPICIOUS_PHRASES = (
    "password",
    "sign in",
    "login",
    "log in",
    "verify account",
    "account verification",
    "security alert",
    "billing update",
    "credit card",
    "confirm identity",
    "suspended",
    "wallet",
    "private key",
    "seed phrase",
)


def extract_page_title(html_content: str) -> Optional[str]:
    match = TITLE_PATTERN.search(html_content)
    if not match:
        return None
    raw_title = match.group(1).strip()
    unescaped = html.unescape(raw_title)
    cleaned = re.sub(r"\s+", " ", unescaped).strip()
    return cleaned if cleaned else None


def detect_password_inputs(html_content: str) -> bool:
    return bool(PASSWORD_INPUT_PATTERN.search(html_content))


def detect_login_forms(html_content: str) -> bool:
    for form_match in FORM_PATTERN.finditer(html_content):
        form_body = form_match.group(1)
        if PASSWORD_INPUT_PATTERN.search(form_body):
            return True
        if re.search(r"""action\s*=\s*['"][^'"]*(?:login|signin|auth|verify)""", form_match.group(0), re.IGNORECASE):
            return True
    return False


def find_suspicious_keywords(html_content: str, target_brand: Optional[str] = None) -> List[str]:
    lowered = html_content.lower()
    matched: List[str] = []
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in lowered:
            matched.append(phrase)
    if target_brand and target_brand.lower() in lowered:
        matched.append(f"brand:{target_brand.lower()}")
    return matched


def analyze_html_content(
    html_content: str, target_brand: Optional[str] = None
) -> ContentAnalysis:
    has_pwd = detect_password_inputs(html_content)
    has_form = detect_login_forms(html_content)
    page_title = extract_page_title(html_content)
    keywords = find_suspicious_keywords(html_content, target_brand)

    risk_score = 0.0
    if has_pwd:
        risk_score += 0.45
    if has_form:
        risk_score += 0.25
    if keywords:
        risk_score += min(0.30, len(keywords) * 0.08)

    normalized_score = max(0.0, min(1.0, round(risk_score, 4)))
    return ContentAnalysis(
        has_password_input=has_pwd,
        has_login_form=has_form,
        page_title=page_title,
        matched_suspicious_keywords=keywords,
        heuristic_risk_score=normalized_score,
    )
