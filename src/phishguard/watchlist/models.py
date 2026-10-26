from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class TargetBrand:
    name: str
    canonical_domains: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)

    def is_legitimate_domain(self, domain: str) -> bool:
        normalized_domain = domain.strip().lower()
        for canonical in self.canonical_domains:
            canonical_normalized = canonical.strip().lower()
            if normalized_domain == canonical_normalized:
                return True
            if normalized_domain.endswith("." + canonical_normalized):
                return True
        return False
