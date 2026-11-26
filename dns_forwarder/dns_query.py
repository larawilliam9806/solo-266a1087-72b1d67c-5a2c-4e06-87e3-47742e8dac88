"""dnslib 底层查询与 TTL 解析（UDP + TCP）。

DNS 的 UDP 答复受报文长度限制，上游可能置 TC（truncated）标记：
此时报文里可能一条 A 记录都没有，也可能只有部分记录，都**不能**当成
完整结果使用。调用方（resolver）收到 ``truncated=True`` 的答复后，
应改用 TCP 向同一上游补查（``query_a_tcp``），页面结果与缓存 TTL
一律以完整答复为准。
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from dnslib import QTYPE, RCODE, RR, DNSQuestion, DNSRecord

from .cache import DEFAULT_NEGATIVE_TTL
from .models import normalize_name

# 单次查询超时（秒）。上游的"答复延迟"是 sleep 之后才回包，
# 所以这里要大于演示允许设置的最大延迟。
DEFAULT_QUERY_TIMEOUT = 10.0


class DnsQueryError(Exception):
    """网络层 / 解析层错误（超时、拒连、坏包等）。"""


@dataclass
class DnsReply:
    rcode: str                       # "NOERROR" / "NXDOMAIN" / ...；截断时为 "TRUNCATED"
    addresses: tuple[str, ...]
    ttl: int                         # 按 DNS 规则计算出的可缓存 TTL
    raw_ttls: tuple[int, ...]        # 报文里实际带的 TTL，便于页面展示
    truncated: bool = False          # UDP 答复带 TC 标记，内容不完整
    transport: str = "udp"           # "udp" / "tcp"


def build_query(name: str) -> DNSRecord:
    qname = normalize_name(name)
    q = DNSRecord()
    q.add_question(DNSQuestion(qname, QTYPE.A))
    q.header.rd = 1
    return q


def _effective_timeout(timeout: float | None) -> float:
    return DEFAULT_QUERY_TIMEOUT if timeout is None else timeout


def _send_udp(q: DNSRecord, host: str, port: int, timeout: float) -> DNSRecord:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(q.pack(), (host, port))
            data, _ = sock.recvfrom(65535)
        finally:
            sock.close()
    except socket.timeout as exc:
        raise DnsQueryError(f"查询 {host}:{port} 超时（{timeout}s）") from exc
    except OSError as exc:
        raise DnsQueryError(f"查询 {host}:{port} 失败: {exc}") from exc

    try:
        reply = DNSRecord.parse(data)
    except Exception as exc:  # dnslib 抛的异常类型比较杂
        raise DnsQueryError(f"无法解析上游回包: {exc}") from exc
    return reply


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise DnsQueryError("TCP 连接被上游关闭")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_tcp(q: DNSRecord, host: str, port: int, timeout: float) -> DNSRecord:
    try:
        sock = socket.create_connection((host, port), timeout)
        try:
            sock.settimeout(timeout)
            payload = q.pack()
            # DNS over TCP：2 字节大端长度前缀 + 报文
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            (length,) = struct.unpack("!H", _recv_exact(sock, 2))
            data = _recv_exact(sock, length)
        finally:
            sock.close()
    except socket.timeout as exc:
        raise DnsQueryError(f"TCP 查询 {host}:{port} 超时（{timeout}s）") from exc
    except DnsQueryError:
        raise
    except OSError as exc:
        raise DnsQueryError(f"TCP 查询 {host}:{port} 失败: {exc}") from exc

    try:
        reply = DNSRecord.parse(data)
    except Exception as exc:  # dnslib 抛的异常类型比较杂
        raise DnsQueryError(f"无法解析上游 TCP 回包: {exc}") from exc
    return reply


def _positive_ttl(records: list[RR]) -> int:
    # RFC 2181：多条 RR 时取最小 TTL
    return min(int(rr.ttl) for rr in records) if records else DEFAULT_NEGATIVE_TTL


def _negative_ttl(reply: DNSRecord) -> int:
    # RFC 2308：NXDOMAIN/NODATA 的 TTL 取权威区 SOA 的 MINIMUM 字段，
    # 且不得超过 SOA 记录自身的 TTL
    soas = [rr for rr in reply.auth if rr.rtype == QTYPE.SOA]
    if soas:
        soa = soas[0]
        minimum = int(soa.rdata.times[4])
        return max(0, min(int(soa.ttl), minimum))
    return DEFAULT_NEGATIVE_TTL


def _parse_reply(reply: DNSRecord, transport: str) -> DnsReply:
    answers = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
    raw_ttls = tuple(int(rr.ttl) for rr in answers)

    # TC 置位说明报文不完整：可能缺记录，也可能只有部分记录。
    # 这里不解析地址/TTL，交由上层用 TCP 向同一上游补查。
    if reply.header.tc:
        return DnsReply(
            "TRUNCATED", (), 0, raw_ttls, truncated=True, transport=transport
        )

    rcode = RCODE.get(reply.header.rcode)

    if rcode == "NXDOMAIN":
        return DnsReply(
            "NXDOMAIN", (), _negative_ttl(reply), raw_ttls, transport=transport
        )

    if rcode != "NOERROR":
        raise DnsQueryError(f"上游返回错误码 {rcode}")

    if not answers:
        # NOERROR 但没有 A 记录 = NODATA，同样按 RFC 2308 做否定缓存
        return DnsReply(
            "NODATA", (), _negative_ttl(reply), raw_ttls, transport=transport
        )

    addresses = tuple(str(rr.rdata) for rr in answers)
    return DnsReply(
        "OK", addresses, _positive_ttl(answers), raw_ttls, transport=transport
    )


def query_a(
    name: str, host: str, port: int, timeout: float | None = None
) -> DnsReply:
    """向单个上游发一次 UDP A 查询。

    若答复带 TC 标记，返回 ``truncated=True``、``addresses=()`` 的
    DnsReply；调用方必须改用 :func:`query_a_tcp` 补查，不能直接使用
    该答复（也不得入缓存）。
    """
    q = build_query(name)
    reply = _send_udp(q, host, port, _effective_timeout(timeout))
    return _parse_reply(reply, "udp")


def query_a_tcp(
    name: str, host: str, port: int, timeout: float | None = None
) -> DnsReply:
    """用 TCP 向同一上游补查 A 记录。

    TCP 不受 UDP 报文长度限制；若答复仍带 TC 标记，说明上游无法给出
    完整结果，按查询失败处理。
    """
    q = build_query(name)
    reply = _send_tcp(q, host, port, _effective_timeout(timeout))
    parsed = _parse_reply(reply, "tcp")
    if parsed.truncated:
        raise DnsQueryError(f"TCP 补查 {host}:{port} 的答复仍带截断标记")
    return parsed
