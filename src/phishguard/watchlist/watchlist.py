import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Union
from phishguard.watchlist.defaults import DEFAULT_TARGET_BRANDS
from phishguard.watchlist.models import TargetBrand


class BrandWatchlist:
    def __init__(self, brands: Optional[Iterable[TargetBrand]] = None) -> None:
        self._brands: Dict[str, TargetBrand] = {}
        if brands:
            for brand in brands:
                self.add_brand(brand)

    def add_brand(self, brand: TargetBrand) -> None:
        normalized_name = brand.name.strip().lower()
        self._brands[normalized_name] = brand

    def get_brand(self, name: str) -> Optional[TargetBrand]:
        return self._brands.get(name.strip().lower())

    def all_brands(self) -> List[TargetBrand]:
        return list(self._brands.values())

    def all_brand_names(self) -> List[str]:
        return list(self._brands.keys())

    def all_search_terms(self) -> List[str]:
        terms: Set[str] = set()
        for brand in self._brands.values():
            terms.add(brand.name.lower())
            for keyword in brand.keywords:
                terms.add(keyword.lower())
        return sorted(terms)

    def is_legitimate_for_brand(self, domain: str, brand_name: str) -> bool:
        brand = self.get_brand(brand_name)
        if not brand:
            return False
        return brand.is_legitimate_domain(domain)

    def is_legitimate_domain(self, domain: str) -> bool:
        for brand in self._brands.values():
            if brand.is_legitimate_domain(domain):
                return True
        return False

    @classmethod
    def from_defaults(cls) -> "BrandWatchlist":
        return cls(DEFAULT_TARGET_BRANDS)

    @classmethod
    def from_json_file(cls, file_path: Union[str, Path]) -> "BrandWatchlist":
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Watchlist file not found: {path}")

        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
        if not isinstance(data, list):
            raise ValueError("Watchlist JSON root must be an array of brand objects")

        brands: List[TargetBrand] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name or not isinstance(name, str):
                continue
            canonical_raw = item.get("canonical_domains", [])
            canonical_domains = (
                [str(d) for d in canonical_raw] if isinstance(canonical_raw, list) else []
            )
            keywords_raw = item.get("keywords", [])
            keywords = (
                [str(k) for k in keywords_raw] if isinstance(keywords_raw, list) else []
            )
            brands.append(
                TargetBrand(
                    name=name,
                    canonical_domains=canonical_domains,
                    keywords=keywords,
                )
            )

        return cls(brands)
