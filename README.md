# dns-resolver-cache

Python DNS 解析缓存库，处理 TTL、CNAME 链、否定缓存、陈旧响应和时钟推进。

## 功能

- 支持 A / AAAA / CNAME 正向响应与 NXDOMAIN / SERVFAIL 否定响应
- 每条缓存记录保存原始 TTL、绝对过期时间和查询类型，键为 `(name, qtype)`，同名不同类型互不干扰
- CNAME 链中每一跳存为独立缓存项，各自拥有独立 TTL；`resolve()` 沿链解析并检测环与深度超限
- 缓存命中返回**剩余 TTL**；过期条目绝不作为新鲜结果返回
- 时间完全由调用方推进（注入 `time_fn`），缓存自身不读取系统时钟

## 用法

```python
from dns_cache import DNSCache, DNSResponse, RecordType, ResourceRecord

cache = DNSCache(time_fn=my_clock)  # my_clock() 返回秒，由调用方推进

cache.put(DNSResponse(
    qname="www.example.com",
    qtype=RecordType.A,
    records=(
        ResourceRecord("www.example.com", RecordType.CNAME, "cdn.example.net", ttl=300),
        ResourceRecord("cdn.example.net", RecordType.A, "192.0.2.1", ttl=100),
    ),
))

result = cache.resolve("www.example.com", RecordType.A)
# result.status == LookupStatus.HIT, result.ttl == 100（剩余 TTL）
```

## 边界行为

- **TTL 为零**：立即过期，永远不会命中为新鲜结果
- **CNAME 环**：`resolve()` 返回 `CNAME_LOOP`；链超过 `max_cname_depth` 返回 `CHAIN_TOO_LONG`；中间跳过期返回 `INCOMPLETE_CHAIN`
- **时钟回拨**：剩余 TTL 被钳制不超过原始 TTL，回拨不会延长条目寿命
- **时钟前跳**：条目按绝对过期时间自然过期

## Stale（陈旧）缓存策略

默认 `allow_stale=False`：条目一过绝对过期时间即失效，访问时被惰性清除，绝不作为新鲜结果返回。

开启 `allow_stale=True` 后，过期条目在 `stale_window` 秒宽限期内仍可作为 **stale** 返回（`stale=True`、`ttl=0`），用于上游故障时兜底。stale 数据永远明确标记、绝不伪装成新鲜数据；超过宽限期后条目被清除。`purge_expired()` 主动清理既非新鲜也不在 stale 窗口内的条目。

## Negative（否定）缓存策略

- **NXDOMAIN**：按 RFC 2308 使用响应携带的 SOA 否定 TTL（`negative_ttl`），但强制执行下限 `min_negative_ttl`（默认 60s）。SOA TTL 过小或缺失时按下限缓存，避免解析器对不存在的域名频繁回源。
- **SERVFAIL**：以很短的 `servfail_ttl`（默认 5s）缓存，既避免捶打故障上游，又能快速恢复；设为 0 可禁用。
- 否定缓存同样以 `(name, qtype)` 为键：A 记录的 NXDOMAIN 不影响同名 AAAA 查询，过期后同样立即失效。

## 测试

```
python -m unittest
```
