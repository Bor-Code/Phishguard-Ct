from typing import Any, Dict, Optional
from phishguard.storage.models import FlaggedRecord

SUPPORTED_PROVIDERS = {"generic", "discord", "slack", "telegram"}


def detect_webhook_provider(
    webhook_url: Optional[str],
    explicit_provider: Optional[str] = None,
) -> str:
    if explicit_provider:
        normalized = explicit_provider.strip().lower()
        if normalized in SUPPORTED_PROVIDERS and normalized != "generic":
            return normalized

    if webhook_url:
        lower_url = webhook_url.strip().lower()
        if "discord.com/api/webhooks" in lower_url or "discordapp.com/api/webhooks" in lower_url:
            return "discord"
        if "hooks.slack.com/" in lower_url:
            return "slack"
        if "api.telegram.org/bot" in lower_url:
            return "telegram"

    if explicit_provider and explicit_provider.strip().lower() in SUPPORTED_PROVIDERS:
        return explicit_provider.strip().lower()
    return "generic"


def format_discord_payload(record: FlaggedRecord) -> Dict[str, Any]:
    summary = (
        f"[ALERT] Phishing suspect detected: {record.domain} "
        f"targeting {record.target_brand} with confidence {record.final_confidence_score:.2f}"
    )
    severity_color = 15158332 if record.final_confidence_score >= 0.85 else 16753920
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
        "color": severity_color,
    }
    return {
        "username": "PhishGuard-CT",
        "content": summary,
        "embeds": [embed],
    }


def format_slack_payload(record: FlaggedRecord) -> Dict[str, Any]:
    summary = (
        f"[ALERT] Phishing suspect detected: {record.domain} "
        f"targeting {record.target_brand} with confidence {record.final_confidence_score:.2f}"
    )
    risk_str = ", ".join(record.risk_factors) if record.risk_factors else "None"
    live_str = "Reachable" if record.is_live else "Unreachable"
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "PhishGuard Threat Alert",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{summary}*",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Domain:*\n`{record.domain}`"},
                {"type": "mrkdwn", "text": f"*Target Brand:*\n`{record.target_brand}`"},
                {"type": "mrkdwn", "text": f"*Confidence Score:*\n`{record.final_confidence_score:.4f}`"},
                {"type": "mrkdwn", "text": f"*Reachability:*\n{live_str}"},
                {"type": "mrkdwn", "text": f"*Matched Term:*\n`{record.matched_term}`"},
                {"type": "mrkdwn", "text": f"*Cert Issuer:*\n{record.cert_issuer or 'N/A'}"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*Risk Factors:* {risk_str}"},
            ],
        },
    ]
    return {
        "text": summary,
        "blocks": blocks,
    }


def format_telegram_payload(
    record: FlaggedRecord,
    chat_id: Optional[str] = None,
) -> Dict[str, Any]:
    risk_str = ", ".join(record.risk_factors) if record.risk_factors else "None"
    live_str = "Reachable" if record.is_live else "Unreachable"
    html_message = (
        "<b>PhishGuard Threat Alert</b>\n"
        f"<b>Domain:</b> <code>{record.domain}</code>\n"
        f"<b>Target Brand:</b> <code>{record.target_brand}</code>\n"
        f"<b>Matched Term:</b> <code>{record.matched_term}</code>\n"
        f"<b>Confidence Score:</b> <code>{record.final_confidence_score:.4f}</code>\n"
        f"<b>Status:</b> {live_str}\n"
        f"<b>Risk Factors:</b> {risk_str}"
    )
    payload: Dict[str, Any] = {
        "text": html_message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if chat_id:
        payload["chat_id"] = chat_id
    return payload


def format_alert_payload(
    record: FlaggedRecord,
    provider: str = "generic",
    chat_id: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_provider = provider.strip().lower() if provider else "generic"
    if normalized_provider == "discord":
        return format_discord_payload(record)
    if normalized_provider == "slack":
        return format_slack_payload(record)
    if normalized_provider == "telegram":
        return format_telegram_payload(record, chat_id=chat_id)

    summary = (
        f"[ALERT] Phishing suspect detected: {record.domain} "
        f"targeting {record.target_brand} with confidence {record.final_confidence_score:.2f}"
    )
    discord_data = format_discord_payload(record)
    slack_data = format_slack_payload(record)

    return {
        "event": "phishing_alert",
        "domain": record.domain,
        "target_brand": record.target_brand,
        "final_confidence_score": record.final_confidence_score,
        "content": summary,
        "text": summary,
        "embeds": discord_data["embeds"],
        "blocks": slack_data["blocks"],
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
