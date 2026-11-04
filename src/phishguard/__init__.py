from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phishguard.service import PhishGuardService

__version__ = "1.0.0"
__all__ = ["PhishGuardService", "__version__"]


def __getattr__(name: str):
    if name == "PhishGuardService":
        from phishguard.service import PhishGuardService

        return PhishGuardService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
