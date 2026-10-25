import json
from typing import Any, Dict, List, Optional
from phishguard.ingestion.models import CertificateEvent


def clean_domain(domain_candidate: str) -> Optional[str]:
    cleaned = domain_candidate.strip().lower()
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    elif cleaned.startswith("."):
        cleaned = cleaned[1:]
    if not cleaned or " " in cleaned or "." not in cleaned:
        return None
    return cleaned


def extract_domains_from_leaf(leaf_cert: Dict[str, Any]) -> List[str]:
    raw_domains: List[str] = []
    direct_all_domains = leaf_cert.get("all_domains")
    if isinstance(direct_all_domains, list):
        raw_domains.extend(str(item) for item in direct_all_domains)

    subject = leaf_cert.get("subject", {})
    common_name = subject.get("CN")
    if common_name and isinstance(common_name, str):
        raw_domains.append(common_name)

    extensions = leaf_cert.get("extensions", {})
    san_entries = extensions.get("subjectAltName")
    if isinstance(san_entries, str):
        for part in san_entries.split(","):
            part = part.strip()
            if part.startswith("DNS:"):
                raw_domains.append(part[4:])
            elif part:
                raw_domains.append(part)
    elif isinstance(san_entries, list):
        for part in san_entries:
            if isinstance(part, str):
                raw_domains.append(part)

    seen = set()
    cleaned_domains: List[str] = []
    for candidate in raw_domains:
        normalized = clean_domain(candidate)
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned_domains.append(normalized)
    return cleaned_domains


def extract_issuer_name(leaf_cert: Dict[str, Any]) -> Optional[str]:
    issuer = leaf_cert.get("issuer")
    if isinstance(issuer, dict):
        return issuer.get("O") or issuer.get("CN") or str(issuer)
    if isinstance(issuer, str):
        return issuer
    return None


def parse_dns_entries_message(payload: Dict[str, Any]) -> Optional[CertificateEvent]:
    raw_entries = payload.get("data")
    if not isinstance(raw_entries, list):
        return None
    seen = set()
    cleaned_domains: List[str] = []
    for entry in raw_entries:
        if isinstance(entry, str):
            cleaned = clean_domain(entry)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                cleaned_domains.append(cleaned)
    if not cleaned_domains:
        return None
    return CertificateEvent(
        domains=cleaned_domains,
        source_name="dns_entries",
        raw_payload=payload,
    )


def parse_certificate_update_message(payload: Dict[str, Any]) -> Optional[CertificateEvent]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return None

    leaf_cert = data.get("leaf_cert")
    if not isinstance(leaf_cert, dict):
        return None

    domains = extract_domains_from_leaf(leaf_cert)
    if not domains:
        return None

    issuer = extract_issuer_name(leaf_cert)
    fingerprint = leaf_cert.get("fingerprint")
    not_before = leaf_cert.get("not_before")
    not_after = leaf_cert.get("not_after")

    source_info = data.get("source", {})
    source_name = source_info.get("name") if isinstance(source_info, dict) else None

    return CertificateEvent(
        domains=domains,
        fingerprint=str(fingerprint) if fingerprint else None,
        issuer=issuer,
        not_before=float(not_before) if isinstance(not_before, (int, float)) else None,
        not_after=float(not_after) if isinstance(not_after, (int, float)) else None,
        source_name=source_name,
        raw_payload=payload,
    )


def parse_certstream_message(raw_text: str) -> Optional[CertificateEvent]:
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    message_type = payload.get("message_type")
    if message_type == "dns_entries":
        return parse_dns_entries_message(payload)
    if message_type == "certificate_update":
        return parse_certificate_update_message(payload)
    return None
