from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CertificateEvent:
    domains: List[str]
    fingerprint: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[float] = None
    not_after: Optional[float] = None
    source_name: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)
