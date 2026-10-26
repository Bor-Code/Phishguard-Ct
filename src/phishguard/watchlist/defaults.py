from typing import List
from phishguard.watchlist.models import TargetBrand

DEFAULT_TARGET_BRANDS: List[TargetBrand] = [
    TargetBrand(
        name="paypal",
        canonical_domains=["paypal.com", "paypal.me"],
        keywords=["paypal"],
    ),
    TargetBrand(
        name="apple",
        canonical_domains=["apple.com", "icloud.com"],
        keywords=["apple", "icloud"],
    ),
    TargetBrand(
        name="google",
        canonical_domains=["google.com", "gmail.com"],
        keywords=["google", "gmail"],
    ),
    TargetBrand(
        name="microsoft",
        canonical_domains=["microsoft.com", "live.com", "office.com"],
        keywords=["microsoft", "outlook", "office365"],
    ),
    TargetBrand(
        name="binance",
        canonical_domains=["binance.com", "binance.us"],
        keywords=["binance"],
    ),
    TargetBrand(
        name="amazon",
        canonical_domains=["amazon.com", "amazon.co.uk", "amazon.de"],
        keywords=["amazon", "primevideo"],
    ),
    TargetBrand(
        name="netflix",
        canonical_domains=["netflix.com"],
        keywords=["netflix"],
    ),
    TargetBrand(
        name="coinbase",
        canonical_domains=["coinbase.com"],
        keywords=["coinbase"],
    ),
    TargetBrand(
        name="meta",
        canonical_domains=["facebook.com", "instagram.com", "meta.com"],
        keywords=["facebook", "instagram", "meta"],
    ),
    TargetBrand(
        name="steam",
        canonical_domains=["steampowered.com", "steamcommunity.com"],
        keywords=["steam", "steampowered"],
    ),
]
