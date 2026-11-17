import unittest

from dns_cache import (
    DNSCache,
    DNSResponse,
    LookupStatus,
    RCode,
    RecordType,
    ResourceRecord,
)


class FakeClock:
    """Caller-controlled clock: time only moves when advance/jump is called."""

    def __init__(self, start=1_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds

    def jump(self, seconds):
        self.now += seconds


def a_record(name, ip, ttl):
    return ResourceRecord(name=name, rtype=RecordType.A, value=ip, ttl=ttl)


def cname_record(name, target, ttl):
    return ResourceRecord(name=name, rtype=RecordType.CNAME, value=target, ttl=ttl)


class PositiveCachingTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = DNSCache(time_fn=self.clock)

    def test_hit_returns_remaining_ttl(self):
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 300),),
        ))
        hit = self.cache.get("example.com", RecordType.A)
        self.assertIsNotNone(hit)
        self.assertEqual(hit.ttl, 300)
        self.assertEqual(hit.records[0].value, "192.0.2.1")
        self.clock.advance(120)
        hit = self.cache.get("example.com", RecordType.A)
        self.assertEqual(hit.ttl, 180)

    def test_expired_entry_is_not_fresh(self):
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 60),),
        ))
        self.clock.advance(61)
        self.assertIsNone(self.cache.get("example.com", RecordType.A))
        self.assertEqual(len(self.cache), 0)  # lazily evicted

    def test_ttl_zero_never_hits(self):
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 0),),
        ))
        self.assertIsNone(self.cache.get("example.com", RecordType.A))

    def test_same_name_different_types_are_independent(self):
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 100),),
        ))
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.AAAA,
            records=(ResourceRecord("example.com", RecordType.AAAA, "2001:db8::1", 200),),
        ))
        self.assertEqual(self.cache.get("example.com", RecordType.A).ttl, 100)
        self.assertEqual(self.cache.get("example.com", RecordType.AAAA).ttl, 200)
        self.clock.advance(150)
        self.assertIsNone(self.cache.get("example.com", RecordType.A))
        self.assertEqual(self.cache.get("example.com", RecordType.AAAA).ttl, 50)

    def test_name_normalization(self):
        self.cache.put(DNSResponse(
            qname="Example.COM.", qtype=RecordType.A,
            records=(a_record("Example.COM.", "192.0.2.1", 100),),
        ))
        self.assertIsNotNone(self.cache.get("example.com", RecordType.A))
        self.assertIsNotNone(self.cache.get("EXAMPLE.COM.", RecordType.A))

    def test_rrset_uses_minimum_ttl(self):
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(
                a_record("example.com", "192.0.2.1", 300),
                a_record("example.com", "192.0.2.2", 120),
            ),
        ))
        self.assertEqual(self.cache.get("example.com", RecordType.A).ttl, 120)


class CnameChainTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = DNSCache(time_fn=self.clock)
        # www.example.com -> cdn.example.net -> 192.0.2.1
        self.cache.put(DNSResponse(
            qname="www.example.com", qtype=RecordType.A,
            records=(
                cname_record("www.example.com", "cdn.example.net", 300),
                a_record("cdn.example.net", "192.0.2.1", 100),
            ),
        ))

    def test_each_hop_stored_independently(self):
        cname_hit = self.cache.get("www.example.com", RecordType.CNAME)
        a_hit = self.cache.get("cdn.example.net", RecordType.A)
        self.assertEqual(cname_hit.ttl, 300)
        self.assertEqual(a_hit.ttl, 100)

    def test_resolve_follows_chain(self):
        result = self.cache.resolve("www.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.HIT)
        self.assertEqual(
            [(h.name, h.rtype) for h in result.chain],
            [
                ("www.example.com", RecordType.CNAME),
                ("cdn.example.net", RecordType.A),
            ],
        )
        self.assertEqual(result.ttl, 100)

    def test_chain_breaks_when_final_answer_expires(self):
        self.clock.advance(150)  # A (100s) expired, CNAME (300s) still fresh
        result = self.cache.resolve("www.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.INCOMPLETE_CHAIN)
        self.assertEqual(len(result.chain), 1)  # CNAME hop still known

    def test_chain_breaks_when_cname_expires(self):
        self.clock.advance(301)
        result = self.cache.resolve("www.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.MISS)

    def test_cname_loop_detected(self):
        cache = DNSCache(time_fn=self.clock)
        cache.put(DNSResponse(
            qname="a.example.com", qtype=RecordType.A,
            records=(cname_record("a.example.com", "b.example.com", 300),),
        ))
        cache.put(DNSResponse(
            qname="b.example.com", qtype=RecordType.A,
            records=(cname_record("b.example.com", "a.example.com", 300),),
        ))
        result = cache.resolve("a.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.CNAME_LOOP)

    def test_self_referential_cname_loop(self):
        cache = DNSCache(time_fn=self.clock)
        cache.put(DNSResponse(
            qname="loop.example.com", qtype=RecordType.A,
            records=(cname_record("loop.example.com", "loop.example.com", 300),),
        ))
        result = cache.resolve("loop.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.CNAME_LOOP)

    def test_chain_depth_limit(self):
        cache = DNSCache(time_fn=self.clock, max_cname_depth=4)
        for i in range(10):
            cache.put(DNSResponse(
                qname=f"h{i}.example.com", qtype=RecordType.A,
                records=(cname_record(f"h{i}.example.com", f"h{i+1}.example.com", 300),),
            ))
        result = cache.resolve("h0.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.CHAIN_TOO_LONG)


class NegativeCachingTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = DNSCache(time_fn=self.clock, min_negative_ttl=60)

    def test_nxdomain_cached_with_remaining_ttl(self):
        self.cache.put(DNSResponse(
            qname="missing.example.com", qtype=RecordType.A,
            rcode=RCode.NXDOMAIN, negative_ttl=300,
        ))
        hit = self.cache.get("missing.example.com", RecordType.A)
        self.assertTrue(hit.negative)
        self.assertEqual(hit.rcode, RCode.NXDOMAIN)
        self.assertEqual(hit.ttl, 300)
        self.clock.advance(100)
        self.assertEqual(self.cache.get("missing.example.com", RecordType.A).ttl, 200)

    def test_nxdomain_minimum_ttl_floor(self):
        # SOA TTL of 5 would hammer the origin; floor raises it to 60.
        self.cache.put(DNSResponse(
            qname="missing.example.com", qtype=RecordType.A,
            rcode=RCode.NXDOMAIN, negative_ttl=5,
        ))
        self.assertEqual(self.cache.get("missing.example.com", RecordType.A).ttl, 60)

    def test_nxdomain_missing_soa_ttl_uses_floor(self):
        self.cache.put(DNSResponse(
            qname="missing.example.com", qtype=RecordType.A,
            rcode=RCode.NXDOMAIN,
        ))
        self.assertEqual(self.cache.get("missing.example.com", RecordType.A).ttl, 60)

    def test_nxdomain_expires(self):
        self.cache.put(DNSResponse(
            qname="missing.example.com", qtype=RecordType.A,
            rcode=RCode.NXDOMAIN, negative_ttl=60,
        ))
        self.clock.advance(61)
        self.assertIsNone(self.cache.get("missing.example.com", RecordType.A))

    def test_nxdomain_is_per_qtype(self):
        self.cache.put(DNSResponse(
            qname="missing.example.com", qtype=RecordType.A,
            rcode=RCode.NXDOMAIN, negative_ttl=300,
        ))
        self.assertIsNone(self.cache.get("missing.example.com", RecordType.AAAA))

    def test_resolve_reports_negative(self):
        self.cache.put(DNSResponse(
            qname="missing.example.com", qtype=RecordType.A,
            rcode=RCode.NXDOMAIN, negative_ttl=300,
        ))
        result = self.cache.resolve("missing.example.com", RecordType.A)
        self.assertEqual(result.status, LookupStatus.NEGATIVE)
        self.assertEqual(result.rcode, RCode.NXDOMAIN)

    def test_servfail_cached_briefly(self):
        self.cache.put(DNSResponse(
            qname="broken.example.com", qtype=RecordType.A,
            rcode=RCode.SERVFAIL,
        ))
        hit = self.cache.get("broken.example.com", RecordType.A)
        self.assertTrue(hit.negative)
        self.assertEqual(hit.rcode, RCode.SERVFAIL)
        self.assertEqual(hit.ttl, 5)
        self.clock.advance(6)
        self.assertIsNone(self.cache.get("broken.example.com", RecordType.A))

    def test_servfail_caching_can_be_disabled(self):
        cache = DNSCache(time_fn=self.clock, servfail_ttl=0)
        cache.put(DNSResponse(
            qname="broken.example.com", qtype=RecordType.A,
            rcode=RCode.SERVFAIL,
        ))
        self.assertIsNone(cache.get("broken.example.com", RecordType.A))


class ClockJumpTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = DNSCache(time_fn=self.clock)
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 300),),
        ))

    def test_backward_jump_never_inflates_ttl(self):
        self.clock.advance(200)          # 100s remain
        self.clock.jump(-10_000)         # clock jumps far into the past
        hit = self.cache.get("example.com", RecordType.A)
        self.assertIsNotNone(hit)
        self.assertLessEqual(hit.ttl, 300)

    def test_backward_jump_past_insertion_clamps_to_original_ttl(self):
        self.clock.jump(-500)            # before the entry was inserted
        hit = self.cache.get("example.com", RecordType.A)
        self.assertEqual(hit.ttl, 300)

    def test_forward_jump_expires_entries(self):
        self.clock.jump(10_000)
        self.assertIsNone(self.cache.get("example.com", RecordType.A))


class StaleServingTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = DNSCache(
            time_fn=self.clock, allow_stale=True, stale_window=30,
        )
        self.cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 60),),
        ))

    def test_stale_entry_marked_not_fresh(self):
        self.clock.advance(70)  # 10s past expiry, within stale window
        hit = self.cache.get("example.com", RecordType.A)
        self.assertIsNotNone(hit)
        self.assertTrue(hit.stale)
        self.assertEqual(hit.ttl, 0)

    def test_stale_window_expires(self):
        self.clock.advance(91)  # past expiry + stale window
        self.assertIsNone(self.cache.get("example.com", RecordType.A))

    def test_stale_disabled_by_default(self):
        cache = DNSCache(time_fn=self.clock)
        cache.put(DNSResponse(
            qname="example.com", qtype=RecordType.A,
            records=(a_record("example.com", "192.0.2.1", 60),),
        ))
        self.clock.advance(61)
        self.assertIsNone(cache.get("example.com", RecordType.A))

    def test_purge_expired(self):
        self.clock.advance(70)
        self.assertEqual(self.cache.purge_expired(), 0)  # still serveable stale
        self.clock.advance(30)
        self.assertEqual(self.cache.purge_expired(), 1)
        self.assertEqual(len(self.cache), 0)


if __name__ == "__main__":
    unittest.main()
