"""测试用假 DNS 上游：可配置延迟、可按查询计数切换答复。

同时监听 UDP 与 TCP（同一端口），并支持模拟一种常见故障：
- ``truncate=True`` 的域名：UDP 答复置 TC 标记、带 ``partial_answers``
  条"部分"地址（地址和 TTL 都与完整答复不同）；
- 同一域名的 TCP 答复返回 ``full_answers`` 条完整地址。

``udp_queries`` / ``tcp_queries`` 分别记录两种协议的查询，便于断言
"截断后确实走了 TCP 补查"以及"改路后没有再向旧上游补查"。
"""
from __future__ import annotations

import socket
import socketserver
import struct
import threading
from dataclasses import dataclass

from dnslib import A, QTYPE, RCODE, RR, SOA, DNSRecord


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream: FakeUpstream = self.server.upstream
        try:
            head = self.request.recv(2)
            if len(head) < 2:
                return
            (length,) = struct.unpack("!H", head)
            data = b""
            while len(data) < length:
                chunk = self.request.recv(length - len(data))
                if not chunk:
                    return
                data += chunk
        except OSError:
            return
        if upstream.tcp_close_delay:
            # 拖延一段时间后直接断开，模拟 TCP 补查失败
            upstream._stop.wait(upstream.tcp_close_delay)
            return
        payload = upstream.answer(data, "tcp")
        if payload is None:
            return
        try:
            self.request.sendall(struct.pack("!H", len(payload)) + payload)
        except OSError:
            pass


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@dataclass
class FakeUpstream:
    host: str
    port: int
    ip_base: int
    soa_minimum: int = 30
    delay: float = 0.0
    # 分别拖慢某一种协议（None 表示沿用 delay）
    udp_delay: float | None = None
    tcp_delay: float | None = None
    # >0 时 TCP 连接收到查询后拖延该秒数再断开（模拟补查失败）
    tcp_close_delay: float = 0.0
    # 域名（归一化后）-> 是否模拟 UDP 截断
    truncate_names: set[str] | None = None
    partial_answers: int = 1
    full_answers: int = 3
    partial_ttl: int = 5
    full_ttl: int = 60

    def __post_init__(self):
        if self.truncate_names is None:
            self.truncate_names = set()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.2)
        self._stop = threading.Event()
        self.queries: list[str] = []
        self.udp_queries: list[str] = []
        self.tcp_queries: list[str] = []
        self._lock = threading.Lock()
        # 第 n 次查询（1-based）返回 NXDOMAIN，其余返回 A；用于精确控制
        self.nx_on_calls: set[int] = set()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

        self._tcp_server = _TCPServer((self.host, self.port), _TCPHandler)
        self._tcp_server.upstream = self
        self._tcp_thread = threading.Thread(
            target=self._tcp_server.serve_forever, daemon=True
        )
        self._tcp_thread.start()

    # ---------- 构造答复 ----------
    def _soa(self, ttl: int | None = None) -> RR:
        ttl = self.soa_minimum if ttl is None else ttl
        return RR(
            "mock.internal",
            QTYPE.SOA,
            ttl=ttl,
            rdata=SOA(
                "ns1.mock.internal",
                "admin.mock.internal",
                (1, 7200, 3600, 1209600, self.soa_minimum),
            ),
        )

    def answer(self, data: bytes, protocol: str) -> bytes | None:
        """返回应答报文字节；None 表示请求无法解析。"""
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return None
        qname = str(req.q.qname).rstrip(".").lower()

        delay = self.delay
        if protocol == "tcp" and self.tcp_delay is not None:
            delay = self.tcp_delay
        elif protocol == "udp" and self.udp_delay is not None:
            delay = self.udp_delay
        if delay:
            self._stop.wait(delay)
            if self._stop.is_set():
                return None

        with self._lock:
            self.queries.append(qname)
            call_no = len(self.queries)
            if protocol == "tcp":
                self.tcp_queries.append(qname)
            else:
                self.udp_queries.append(qname)

        reply = req.reply()
        truncated = qname in {n.lower().rstrip(".") for n in self.truncate_names}

        if call_no in self.nx_on_calls:
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(self._soa())
        elif truncated and protocol == "udp":
            # UDP：置 TC，只带部分（或 0 条）地址（地址与 TTL 都与完整答复不同）
            reply.header.tc = 1
            for i in range(max(0, self.partial_answers)):
                reply.add_answer(
                    RR(
                        qname,
                        QTYPE.A,
                        ttl=self.partial_ttl,
                        rdata=A(f"{self.ip_base}.1.1.{i + 1}"),
                    )
                )
        elif truncated:
            # TCP：完整地址
            for i in range(max(1, self.full_answers)):
                reply.add_answer(
                    RR(
                        qname,
                        QTYPE.A,
                        ttl=self.full_ttl,
                        rdata=A(f"{self.ip_base}.9.9.{i + 1}"),
                    )
                )
        else:
            reply.add_answer(
                RR(qname, QTYPE.A, ttl=60, rdata=A(f"{self.ip_base}.0.0.{call_no}"))
            )
        return reply.pack()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            payload = self.answer(data, "udp")
            if payload is None:
                continue
            try:
                self._sock.sendto(payload, addr)
            except OSError:
                return

    @property
    def query_count(self) -> int:
        with self._lock:
            return len(self.queries)

    @property
    def udp_query_count(self) -> int:
        with self._lock:
            return len(self.udp_queries)

    @property
    def tcp_query_count(self) -> int:
        with self._lock:
            return len(self.tcp_queries)

    def stop(self):
        self._stop.set()
        self._tcp_server.shutdown()
        self._tcp_server.server_close()
        self._sock.close()
        self._thread.join(timeout=2)
        self._tcp_thread.join(timeout=2)
