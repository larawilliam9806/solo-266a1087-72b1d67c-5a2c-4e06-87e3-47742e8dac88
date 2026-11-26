"""异步解析编排。

关键并发语义：
- 阻塞的 UDP / TCP 查询放在线程池里执行，事件循环不被阻塞，
  等待回包期间页面照常改规则、查别的域名；
- 回包后先用 RuleStore.is_stale() 校验等待期间命中规则是否被动过。
  被动过（哪怕又改回原样）就丢弃回包、按现行规则从 UDP 重新查询；
- 陈旧回包绝不写入缓存；只有现行规则下的回包才按 TTL 入缓存。
- UDP 答复带 TC（truncated）标记时内容不完整（可能缺记录，也可能
  只有部分地址），必须改用 TCP 向**同一上游**补查；页面结果和缓存
  TTL 一律以 TCP 完整答复为准。
- TCP 补查在途期间同样可能改规则：补查完成后再次校验，规则变了就
  丢掉旧答复或错误、按现行规则从 UDP 重查；
- 现行规则下 TCP 补查失败或答复仍带截断标记 -> 解析失败，本次不入缓存。
"""
from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from .cache import CacheEntry, DnsCache
from .dns_query import DnsQueryError, DnsReply, query_a, query_a_tcp
from .models import normalize_name
from .rules import Rule, RuleStore
from .upstream import Upstream, UpstreamRegistry

MAX_REATTEMPTS = 6  # 等待期间规则反复变化时的重查上限，防止极端情况下无限循环


class Resolver:
    def __init__(
        self,
        rules: RuleStore,
        cache: DnsCache,
        upstreams: UpstreamRegistry,
        max_workers: int = 32,
        query_timeout: float | None = None,
    ):
        self.rules = rules
        self.cache = cache
        self.upstreams = upstreams
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dns-query"
        )
        self._timeout = query_timeout

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)

    async def _run_query(self, func, key: str, upstream: Upstream) -> DnsReply:
        """把阻塞的查询丢进线程池，事件循环保持可响应。"""
        call = partial(func, key, upstream.host, upstream.dns_port, self._timeout)
        return await asyncio.get_running_loop().run_in_executor(self._pool, call)

    def _stale(self, key: str, rule: Rule) -> bool:
        return self.rules.is_stale(key, rule.suffix, rule.version)

    async def resolve(self, name: str) -> dict:
        key = normalize_name(name)
        started = time.monotonic()

        # 1. 缓存优先（惰性过期，命中即返回）
        cached = self.cache.get(key)
        if cached is not None:
            return self._result(
                key, cached, cached_hit=True, stale_discarded=0, elapsed=time.monotonic() - started
            )

        stale_discarded = 0
        last_error: str | None = None

        # 2. 规则 -> 上游 -> UDP 查询；截断则 TCP 补查；陈旧回包丢弃重查
        for _ in range(MAX_REATTEMPTS):
            rule: Rule = self.rules.match(key)
            upstream = self.upstreams.get(rule.upstream_id)

            try:
                reply: DnsReply = await self._run_query(query_a, key, upstream)
            except DnsQueryError as exc:
                # 连答复都没等到规则就变了：按现行规则重查，不把旧错误当结论
                if self._stale(key, rule):
                    stale_discarded += 1
                    continue
                last_error = str(exc)
                break

            # 3. 等待期间规则被动过？丢包，按现行规则从 UDP 重来
            if self._stale(key, rule):
                stale_discarded += 1
                continue

            # 4. UDP 答复被截断：丢弃不完整内容，TCP 向同一上游补查。
            #    （旧上游的 TCP 补查绝不发起——上面已经按现行规则校验过）
            udp_truncated = reply.truncated
            if udp_truncated:
                try:
                    reply = await self._run_query(query_a_tcp, key, upstream)
                except DnsQueryError as exc:
                    # TCP 补查已发出后才改路：旧答复/错误作废，按现行规则重查
                    if self._stale(key, rule):
                        stale_discarded += 1
                        continue
                    last_error = f"UDP 答复被截断，TCP 补查失败: {exc}"
                    break

                # TCP 在途期间规则同样可能被改：旧答复作废，从 UDP 重查
                if self._stale(key, rule):
                    stale_discarded += 1
                    continue

            # 5. 现行规则下的完整答复：按 TTL 入缓存
            now = time.monotonic()
            entry = CacheEntry(
                key=key,
                status=reply.rcode,
                addresses=reply.addresses,
                ttl=max(1, reply.ttl),
                upstream_id=upstream.id,
                suffix=rule.suffix,
                expire_at=now + max(1, reply.ttl),
                created_at=now,
                transport=reply.transport,
                udp_truncated=udp_truncated,
            )
            self.cache.put(entry)
            return self._result(
                key, entry, cached_hit=False, stale_discarded=stale_discarded,
                elapsed=time.monotonic() - started, raw_ttls=reply.raw_ttls,
            )

        if stale_discarded and last_error is None:
            last_error = "规则在等待期间多次变更，重查次数达到上限"
        return {
            "name": key,
            "cached_hit": False,
            "stale_discarded": stale_discarded,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "status": "ERROR",
            "error": last_error or "解析失败",
        }

    @staticmethod
    def _result(
        key: str,
        entry: CacheEntry,
        cached_hit: bool,
        stale_discarded: int,
        elapsed: float,
        raw_ttls: tuple[int, ...] | None = None,
    ) -> dict:
        body = entry.to_dict()
        body.update(
            {
                "name": key,
                "cached_hit": cached_hit,
                "stale_discarded": stale_discarded,
                "elapsed_ms": round(elapsed * 1000, 1),
                "raw_ttls": list(raw_ttls or []),
            }
        )
        return body
