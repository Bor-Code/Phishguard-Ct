from typing import TYPE_CHECKING
from phishguard.ingestion.models import CertificateEvent

if TYPE_CHECKING:
    from phishguard.ingestion.client import CertstreamClient

__all__ = ["CertstreamClient", "CertificateEvent"]


def __getattr__(name: str):
    if name == "CertstreamClient":
        from phishguard.ingestion.client import CertstreamClient

        return CertstreamClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
