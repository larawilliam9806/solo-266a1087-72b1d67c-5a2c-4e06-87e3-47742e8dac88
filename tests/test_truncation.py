"""UDP 截断 -> TCP 向同一上游补查的语义。

覆盖：
- 截断答复（无 A 记录 / 只有部分地址）不得误报 NODATA、不得当成完整结果缓存；
- 页面结果与缓存 TTL 以 TCP 完整答复为准；
- 补查前后等待期间改规则：按现行规则从 UDP 重查，跳过旧上游补查；
- TCP 补查已发出后才改路：旧答复/错误作废；
- 现行规则下 TCP 补查失败 / 仍截断：解析失败且不入缓存。
"""
from __future__ import annotations

import socket

import pytest

from dns_forwarder.cache import DnsCache
from dns_forwarder.resolver import Resolver
from dns_forwarder.rules import RuleStore
from dns_forwarder.upstream import Upstream, UpstreamRegistry

from .fakes import FakeUpstream


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def harness():
    port_a, port_b = _free_port(), _free_port()
    fake_a = FakeUpstream(
        "127.0.0.1", port_a, ip_base=10,
        truncate_names={"trunc.corp.local"}, partial_answers=1,
        full_answers=3, partial_ttl=5, full_ttl=60,
    )
    fake_b = FakeUpstream(
        "127.0.0.1", port_b, ip_base=172,
        truncate_names={"trunc.corp.local"}, partial_answers=1,
        full_answers=3, partial_ttl=5, full_ttl=60,
    )
    registry = UpstreamRegistry(
        [
            Upstream("upstream-a", "A", "127.0.0.1", port_a, 1),
            Upstream("upstream-b", "B", "127.0.0.1", port_b, 2),
        ]
    )
    rules = RuleStore("upstream-a")
    cache = DnsCache()
    resolver = Resolver(rules, cache, registry)
    yield fake_a, fake_b, rules, cache, resolver
    resolver.shutdown()
    fake_a.stop()
    fake_b.stop()


# ---------- 基本行为 ----------

def test_truncated_udp_with_partial_addresses_uses_tcp_full_answer(harness):
    fake_a, _, _, cache, resolver = harness

    result = __import__("asyncio").run(resolver.resolve("trunc.corp.local"))

    assert result["status"] == "OK"
    # TCP 完整答复的 3 条地址，而不是 UDP 里那 1 条部分地址
    assert result["addresses"] == ["10.9.9.1", "10.9.9.2", "10.9.9.3"]
    assert result["transport"] == "tcp"
    assert result["udp_truncated"] is True
    # 缓存 TTL 取自 TCP 完整答复，而不是 UDP 部分答复的 5s
    assert result["ttl"] == 60
    assert fake_a.udp_query_count == 1
    assert fake_a.tcp_query_count == 1

    entry = cache.get("trunc.corp.local")
    assert entry is not None
    assert entry.addresses == ("10.9.9.1", "10.9.9.2", "10.9.9.3")
    assert entry.ttl == 60
    assert entry.transport == "tcp" and entry.udp_truncated is True


def test_truncated_udp_without_answers_not_reported_as_nodata(harness):
    fake_a, _, _, cache, resolver = harness
    fake_a.partial_answers = 0  # 截断报文里一条 A 记录都没有

    result = __import__("asyncio").run(resolver.resolve("trunc.corp.local"))

    assert result["status"] == "OK"
    assert result["addresses"] == ["10.9.9.1", "10.9.9.2", "10.9.9.3"]
    assert result["ttl"] == 60
    assert fake_a.tcp_query_count == 1
    assert cache.get("trunc.corp.local").status == "OK"


def test_complete_udp_answer_does_not_use_tcp(harness):
    fake_a, _, _, _, resolver = harness

    result = __import__("asyncio").run(resolver.resolve("host.corp.local"))

    assert result["status"] == "OK"
    assert result["transport"] == "udp" and result["udp_truncated"] is False
    assert fake_a.udp_query_count == 1
    assert fake_a.tcp_query_count == 0


# ---------- 等待 TCP 补查期间改规则 ----------

def test_rule_change_while_waiting_for_tcp_discards_old_answer(harness):
    """UDP 已截断、TCP 补查在途时改路：旧答复作废，按现行规则从 UDP 重查。"""
    import asyncio

    fake_a, fake_b, rules, cache, resolver = harness
    fake_a.delay = 0.0
    fake_a.tcp_delay = 0.6  # 拖慢 A 的 TCP 补查
    fake_b.delay = 0.0

    async def scenario():
        task = asyncio.create_task(resolver.resolve("trunc.corp.local"))
        # 等 UDP 截断答复回来、TCP 补查发出之后再改路
        await asyncio.sleep(0.15)
        rules.set_rule("", "upstream-b")
        return await task

    result = asyncio.run(scenario())

    assert result["stale_discarded"] >= 1
    assert result["upstream_id"] == "upstream-b"
    # 结果来自 B 的 TCP 完整答复
    assert result["addresses"] == ["172.9.9.1", "172.9.9.2", "172.9.9.3"]
    assert result["ttl"] == 60
    # 旧上游 A 的 TCP 补查即使走完也绝不入缓存
    entry = cache.get("trunc.corp.local")
    assert entry is not None and entry.upstream_id == "upstream-b"
    assert fake_a.tcp_query_count == 1  # 旧补查确已发出
    assert fake_b.tcp_query_count == 1


def test_rule_change_after_udp_before_tcp_skips_old_upstream_tcp(harness):
    """UDP 截断答复回来时规则已变：跳过旧上游的 TCP 补查，直接按现行规则重查。"""
    import asyncio

    fake_a, fake_b, rules, cache, resolver = harness
    fake_a.delay = 0.0
    fake_a.udp_delay = 0.5  # UDP 答复慢，留出改路窗口

    async def scenario():
        task = asyncio.create_task(resolver.resolve("trunc.corp.local"))
        await asyncio.sleep(0.15)  # UDP 还在途
        rules.set_rule("", "upstream-b")
        return await task

    result = asyncio.run(scenario())

    assert result["upstream_id"] == "upstream-b"
    assert result["addresses"] == ["172.9.9.1", "172.9.9.2", "172.9.9.3"]
    assert result["stale_discarded"] == 1
    # 旧上游 A 的 UDP 截断答复被丢弃，从未向 A 发起 TCP 补查
    assert fake_a.tcp_query_count == 0
    assert fake_b.tcp_query_count == 1


def test_change_back_during_tcp_still_discards_old_answer(harness):
    """TCP 补查在途时改到 B 又改回 A：旧答复因版本变化照样作废。"""
    import asyncio

    fake_a, fake_b, rules, cache, resolver = harness
    fake_a.delay = 0.0
    fake_a.tcp_delay = 0.5

    async def scenario():
        task = asyncio.create_task(resolver.resolve("trunc.corp.local"))
        await asyncio.sleep(0.15)  # TCP 补查已发出
        rules.set_rule("", "upstream-b")
        rules.set_rule("", "upstream-a")
        return await task

    result = asyncio.run(scenario())

    assert result["stale_discarded"] >= 1
    assert result["upstream_id"] == "upstream-a"
    # 第一次 TCP 补查的答复被丢弃后，从 UDP 重查、再补一次 TCP
    assert fake_a.tcp_query_count >= 2
    entry = cache.get("trunc.corp.local")
    assert entry is not None and entry.upstream_id == "upstream-a"


def test_edit_rules_and_query_others_while_tcp_pending(harness):
    """等待 TCP 补查期间页面仍可改规则、查别的域名（事件循环不被阻塞）。"""
    import asyncio

    fake_a, fake_b, rules, cache, resolver = harness
    fake_a.delay = 0.0
    fake_a.tcp_delay = 0.6
    rules.set_rule("other.test", "upstream-b")

    async def scenario():
        slow = asyncio.create_task(resolver.resolve("trunc.corp.local"))
        await asyncio.sleep(0.1)  # UDP 已截断，TCP 补查在途
        rules.set_rule("fast.test", "upstream-a")  # 可改规则
        quick = await asyncio.wait_for(
            resolver.resolve("quick.fast.test"), timeout=0.5
        )
        return await slow, quick

    slow_result, quick_result = asyncio.run(scenario())

    assert quick_result["status"] == "OK"
    assert quick_result["upstream_id"] == "upstream-a"
    assert quick_result["addresses"] and quick_result["addresses"][0].startswith("10.")
    assert slow_result["addresses"] == ["10.9.9.1", "10.9.9.2", "10.9.9.3"]
    assert fake_a.tcp_query_count == 1


# ---------- TCP 补查失败 ----------

def test_tcp_failure_reports_error_and_does_not_cache(harness):
    fake_a, _, _, cache, resolver = harness
    # 关掉 A 的 TCP 监听，UDP 仍能答复并在截断
    fake_a._tcp_server.shutdown()
    fake_a._tcp_server.server_close()

    import asyncio

    result = asyncio.run(resolver.resolve("trunc.corp.local"))

    assert result["status"] == "ERROR"
    assert "TCP" in result["error"]
    assert cache.get("trunc.corp.local") is None
    assert cache.stats()["entries"] == 0


def test_tcp_reply_truncated_again_reports_error_and_does_not_cache(harness):
    """TCP 答复仍带 TC：视为上游无法给出完整结果，解析失败且不入缓存。"""
    fake_a, _, _, cache, resolver = harness

    # 让 TCP 路径也置 TC —— 通过包一层 resolver 实现
    original_answer = fake_a.answer

    def answer_with_tcp_truncation(data, protocol):
        payload = original_answer(data, protocol)
        if payload is None or protocol != "tcp":
            return payload
        from dnslib import DNSRecord

        reply = DNSRecord.parse(payload)
        reply.header.tc = 1
        return reply.pack()

    fake_a.answer = answer_with_tcp_truncation

    import asyncio

    result = asyncio.run(resolver.resolve("trunc.corp.local"))

    assert result["status"] == "ERROR"
    assert "截断" in result["error"]
    assert cache.get("trunc.corp.local") is None


def test_tcp_failure_after_rule_change_is_discarded(harness):
    """TCP 补查已发出、失败前改路：旧错误作废，按现行规则从 UDP 重查。"""
    import asyncio

    fake_a, fake_b, rules, cache, resolver = harness
    fake_a.delay = 0.0
    fake_a.tcp_close_delay = 0.6  # A 的 TCP 补查会在 0.6s 后失败

    async def scenario():
        task = asyncio.create_task(resolver.resolve("trunc.corp.local"))
        await asyncio.sleep(0.15)  # TCP 补查已发出
        rules.set_rule("", "upstream-b")
        return await task

    result = asyncio.run(scenario())

    # 旧上游的失败被丢弃，结果来自现行规则 B 的完整 TCP 答复
    assert result["status"] == "OK"
    assert result["upstream_id"] == "upstream-b"
    assert result["addresses"] == ["172.9.9.1", "172.9.9.2", "172.9.9.3"]
    assert result["stale_discarded"] >= 1
    entry = cache.get("trunc.corp.local")
    assert entry is not None and entry.upstream_id == "upstream-b"
