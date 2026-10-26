from typing import Any, Dict
from phishguard.storage.models import FlaggedRecord


def format_alert_payload(record: FlaggedRecord) -> Dict[str, Any]:
    summary = (
        f"[ALERT] Phishing suspect detected: {record.domain} "
        f"targeting {record.target_brand} with confidence {record.final_confidence_score:.2f}"
    )

    embed_fields = [
        {"name": "Domain", "value": record.domain, "inline": True},
        {"name": "Target Brand", "value": record.target_brand, "inline": True},
        {"name": "Confidence Score", "value": f"{record.final_confidence_score:.4f}", "inline": True},
        {"name": "Matched Term", "value": record.matched_term, "inline": True},
        {"name": "Reachability", "value": "Reachable" if record.is_live else "Unreachable", "inline": True},
        {"name": "Certificate Issuer", "value": record.cert_issuer or "N/A", "inline": True},
        {
            "name": "Risk Factors",
            "value": ", ".join(record.risk_factors) if record.risk_factors else "None",
            "inline": False,
        },
    ]

    embed = {
        "title": "PhishGuard Threat Alert",
        "description": summary,
        "fields": embed_fields,
        "color": 15158332,
    }

    return {
        "event": "phishing_alert",
        "domain": record.domain,
        "target_brand": record.target_brand,
        "final_confidence_score": record.final_confidence_score,
        "content": summary,
        "text": summary,
        "embeds": [embed],
        "details": {
            "matched_term": record.matched_term,
            "composite_score": record.composite_score,
            "is_live": record.is_live,
            "http_status": record.http_status,
            "final_url": record.final_url,
            "cert_issuer": record.cert_issuer,
            "risk_factors": record.risk_factors,
            "status": record.status,
            "detected_at": record.detected_at,
        },
    }
