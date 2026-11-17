"""Core DNS resolver cache.

Stores A / AAAA / CNAME / NXDOMAIN / SERVFAIL responses with their
original TTL and absolute expiry time.  Time is always supplied by the
caller (via an injectable clock), which makes expiry deterministic and
testable.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


class RecordType(enum.Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"


class RCode(enum.Enum):
    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"


class LookupStatus(enum.Enum):
    HIT = "HIT"
    MISS = "MISS"
    NEGATIVE = "NEGATIVE"
    STALE = "STALE"
    CNAME_LOOP = "CNAME_LOOP"
    CHAIN_TOO_LONG = "CHAIN_TOO_LONG"
    INCOMPLETE_CHAIN = "INCOMPLETE_CHAIN"


def normalize_name(name: str) -> str:
    """Canonicalize a DNS name for cache keys."""
    return name.rstrip(".").lower()


@dataclass(frozen=True)
class ResourceRecord:
    name: str
    rtype: RecordType
    value: str
    ttl: int


@dataclass(frozen=True)
class DNSResponse:
    """A resolver response fed into the cache.

    ``negative_ttl`` carries the SOA-derived negative caching TTL for
    NXDOMAIN responses (RFC 2308); it is ignored for other rcodes.
    """

    qname: str
    qtype: RecordType
    rcode: RCode = RCode.NOERROR
    records: Tuple[ResourceRecord, ...] = ()
    negative_ttl: Optional[int] = None


@dataclass
class CacheEntry:
    records: Tuple[ResourceRecord, ...]
    original_ttl: int
    inserted_at: float
    expires_at: float
    negative: bool = False
    rcode: RCode = RCode.NOERROR

    def remaining_ttl(self, now: float) -> int:
        remaining = self.expires_at - now
        if remaining <= 0:
            return 0
        # A backward clock jump must never inflate the remaining TTL
        # beyond what the origin originally granted.
        return min(int(remaining), self.original_ttl)

    def is_fresh(self, now: float) -> bool:
        return self.remaining_ttl(now) > 0


@dataclass
class CacheHit:
    records: Tuple[ResourceRecord, ...]
    ttl: int
    rcode: RCode
    negative: bool = False
    stale: bool = False


@dataclass
class ChainHop:
    name: str
    rtype: RecordType
    records: Tuple[ResourceRecord, ...]
    ttl: int


@dataclass
class ResolveResult:
    status: LookupStatus
    chain: List[ChainHop] = field(default_factory=list)
    rcode: RCode = RCode.NOERROR
    ttl: int = 0
    stale: bool = False


class DNSCache:
    """TTL-aware DNS cache with CNAME chains and negative caching.

    Parameters
    ----------
    time_fn:
        Clock callable returning seconds.  The caller advances time;
        the cache never reads the wall clock on its own if one is given.
    min_negative_ttl:
        Floor (seconds) applied to NXDOMAIN caching so a tiny/absent
        SOA TTL cannot force the resolver back to the origin constantly.
    servfail_ttl:
        How long SERVFAIL responses are cached (short, to avoid
        hammering a failing upstream).  0 disables SERVFAIL caching.
    max_cname_depth:
        Maximum CNAME hops followed before giving up.
    allow_stale:
        If true, expired entries may be served as *stale* (ttl=0,
        stale=True) for ``stale_window`` seconds past expiry, e.g. to
        cover an outage.  Stale data is never reported as fresh.
    stale_window:
        Seconds after expiry during which stale data may be served.
    """

    def __init__(
        self,
        time_fn: Callable[[], float] = time.monotonic,
        min_negative_ttl: int = 60,
        servfail_ttl: int = 5,
        max_cname_depth: int = 8,
        allow_stale: bool = False,
        stale_window: float = 30.0,
    ) -> None:
        self._time_fn = time_fn
        self.min_negative_ttl = min_negative_ttl
        self.servfail_ttl = servfail_ttl
        self.max_cname_depth = max_cname_depth
        self.allow_stale = allow_stale
        self.stale_window = stale_window
        self._entries: Dict[Tuple[str, RecordType], CacheEntry] = {}

    # -- time -----------------------------------------------------------

    def _now(self) -> float:
        return float(self._time_fn())

    # -- insertion ------------------------------------------------------

    def put(self, response: DNSResponse) -> None:
        now = self._now()
        if response.rcode in (RCode.NXDOMAIN, RCode.SERVFAIL):
            self._put_negative(response, now)
            return
        self._put_positive(response, now)

    def _put_negative(self, response: DNSResponse, now: float) -> None:
        if response.rcode is RCode.NXDOMAIN:
            ttl = max(response.negative_ttl or 0, self.min_negative_ttl)
        else:  # SERVFAIL
            ttl = self.servfail_ttl
        if ttl <= 0:
            return
        key = (normalize_name(response.qname), response.qtype)
        self._entries[key] = CacheEntry(
            records=(),
            original_ttl=ttl,
            inserted_at=now,
            expires_at=now + ttl,
            negative=True,
            rcode=response.rcode,
        )

    def _put_positive(self, response: DNSResponse, now: float) -> None:
        groups: Dict[Tuple[str, RecordType], List[ResourceRecord]] = {}
        for record in response.records:
            key = (normalize_name(record.name), record.rtype)
            groups.setdefault(key, []).append(record)
        for key, records in groups.items():
            # RRsets must share one TTL; take the most conservative.
            ttl = min(r.ttl for r in records)
            self._entries[key] = CacheEntry(
                records=tuple(records),
                original_ttl=ttl,
                inserted_at=now,
                expires_at=now + ttl,
            )

    # -- lookup ---------------------------------------------------------

    def get(self, name: str, qtype: RecordType) -> Optional[CacheHit]:
        """Look up a single (name, qtype) entry.

        Returns a CacheHit with the *remaining* TTL, or None on miss.
        Expired entries are never returned as fresh; they are evicted
        unless stale serving is enabled and still within the window.
        """
        now = self._now()
        key = (normalize_name(name), qtype)
        entry = self._entries.get(key)
        if entry is None:
            return None
        remaining = entry.remaining_ttl(now)
        if remaining > 0:
            return CacheHit(
                records=entry.records,
                ttl=remaining,
                rcode=entry.rcode,
                negative=entry.negative,
            )
        if self.allow_stale and now - entry.expires_at <= self.stale_window:
            return CacheHit(
                records=entry.records,
                ttl=0,
                rcode=entry.rcode,
                negative=entry.negative,
                stale=True,
            )
        del self._entries[key]
        return None

    def resolve(self, name: str, qtype: RecordType) -> ResolveResult:
        """Follow the CNAME chain for (name, qtype) using cached hops.

        Each hop of a CNAME chain is an independent cache entry with its
        own TTL; the chain only resolves while every hop is fresh.
        """
        chain: List[ChainHop] = []
        seen = set()
        current = normalize_name(name)
        while True:
            if current in seen:
                return ResolveResult(LookupStatus.CNAME_LOOP, chain)
            seen.add(current)
            if len(chain) >= self.max_cname_depth:
                return ResolveResult(LookupStatus.CHAIN_TOO_LONG, chain)

            hit = self.get(current, qtype)
            if hit is not None:
                if hit.negative:
                    return ResolveResult(
                        LookupStatus.NEGATIVE, chain, rcode=hit.rcode, ttl=hit.ttl
                    )
                chain.append(ChainHop(current, qtype, hit.records, hit.ttl))
                return ResolveResult(
                    LookupStatus.HIT,
                    chain,
                    rcode=RCode.NOERROR,
                    ttl=hit.ttl,
                    stale=hit.stale,
                )

            if qtype is not RecordType.CNAME:
                cname_hit = self.get(current, RecordType.CNAME)
                if cname_hit is not None and not cname_hit.negative:
                    target = normalize_name(cname_hit.records[0].value)
                    chain.append(
                        ChainHop(
                            current,
                            RecordType.CNAME,
                            cname_hit.records,
                            cname_hit.ttl,
                        )
                    )
                    current = target
                    continue

            status = LookupStatus.INCOMPLETE_CHAIN if chain else LookupStatus.MISS
            return ResolveResult(status, chain)

    # -- maintenance ----------------------------------------------------

    def purge_expired(self) -> int:
        """Drop entries that can no longer be served (fresh or stale)."""
        now = self._now()
        doomed = []
        for key, entry in self._entries.items():
            if entry.is_fresh(now):
                continue
            if self.allow_stale and now - entry.expires_at <= self.stale_window:
                continue
            doomed.append(key)
        for key in doomed:
            del self._entries[key]
        return len(doomed)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: Tuple[str, RecordType]) -> bool:
        name, qtype = key
        return (normalize_name(name), qtype) in self._entries
