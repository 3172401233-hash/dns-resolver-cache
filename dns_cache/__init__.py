"""TTL-aware DNS resolver cache."""

from .cache import (
    CacheEntry,
    CacheHit,
    ChainHop,
    DNSCache,
    DNSResponse,
    LookupStatus,
    RCode,
    RecordType,
    ResolveResult,
    ResourceRecord,
    normalize_name,
)

__all__ = [
    "CacheEntry",
    "CacheHit",
    "ChainHop",
    "DNSCache",
    "DNSResponse",
    "LookupStatus",
    "RCode",
    "RecordType",
    "ResolveResult",
    "ResourceRecord",
    "normalize_name",
]
