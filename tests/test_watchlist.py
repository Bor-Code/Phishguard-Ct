import json
import pytest
from phishguard.config import Settings
from phishguard.watchlist import BrandWatchlist, TargetBrand


def test_target_brand_legitimate_domain():
    brand = TargetBrand(
        name="paypal",
        canonical_domains=["paypal.com", "paypal.me"],
        keywords=["paypal"],
    )
    assert brand.is_legitimate_domain("paypal.com") is True
    assert brand.is_legitimate_domain("subdomain.paypal.com") is True
    assert brand.is_legitimate_domain("paypal.me") is True
    assert brand.is_legitimate_domain("paypal-security.com") is False
    assert brand.is_legitimate_domain("paypa1.com") is False
    assert brand.is_legitimate_domain("evilpaypal.com") is False


def test_brand_watchlist_defaults():
    watchlist = BrandWatchlist.from_defaults()
    assert len(watchlist.all_brands()) >= 10
    assert "paypal" in watchlist.all_brand_names()
    assert "google" in watchlist.all_brand_names()
    assert watchlist.is_legitimate_domain("mail.google.com") is True
    assert watchlist.is_legitimate_domain("google-verify.com") is False


def test_brand_watchlist_from_json_file(tmp_path):
    custom_brands = [
        {
            "name": "custombank",
            "canonical_domains": ["custombank.com"],
            "keywords": ["custombank", "cbank"],
        }
    ]
    file_path = tmp_path / "custom_brands.json"
    file_path.write_text(json.dumps(custom_brands), encoding="utf-8")

    watchlist = BrandWatchlist.from_json_file(file_path)
    brand = watchlist.get_brand("custombank")
    assert brand is not None
    assert brand.name == "custombank"
    assert "cbank" in watchlist.all_search_terms()
    assert watchlist.is_legitimate_for_brand("login.custombank.com", "custombank") is True


def test_brand_watchlist_from_invalid_file(tmp_path):
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text(json.dumps({"not": "a list"}), encoding="utf-8")

    with pytest.raises(ValueError):
        BrandWatchlist.from_json_file(invalid_file)

    with pytest.raises(FileNotFoundError):
        BrandWatchlist.from_json_file(tmp_path / "non_existent.json")


def test_settings_defaults(monkeypatch):
    monkeypatch.delenv("CERTSTREAM_URL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("MIN_ALERT_SCORE", raising=False)

    settings = Settings.from_env()
    assert settings.certstream_url == "wss://api.certstream.dev/domains-only"
    assert settings.alert_webhook_url is None
    assert settings.min_alert_score == 0.75
    assert settings.database_path == "phishguard.db"


def test_settings_custom_env(monkeypatch):
    monkeypatch.setenv("CERTSTREAM_URL", "wss://custom.stream/ct")
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.local/alert")
    monkeypatch.setenv("MIN_ALERT_SCORE", "0.85")

    settings = Settings.from_env()
    assert settings.certstream_url == "wss://custom.stream/ct"
    assert settings.alert_webhook_url == "https://hooks.local/alert"
    assert settings.min_alert_score == 0.85
