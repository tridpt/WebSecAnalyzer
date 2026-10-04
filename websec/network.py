"""Pin verified DNS answers at the socket layer while retaining Host and SNI."""

from __future__ import annotations

import ipaddress
import socket
import threading
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from .control import ScanControl
from .targets import InvalidTarget, is_loopback_host


class DNSChanged(InvalidTarget):
    """A hostname no longer resolves to its originally verified address."""


class PinnedDNS:
    def __init__(self, *, allow_private: bool, control: ScanControl | None = None):
        self.allow_private = allow_private
        self.control = control
        self.addresses: dict[tuple[str, int], str] = {}

    def verify(self, host: str, port: int) -> str:
        if self.control:
            self.control.check()
        key = (host.lower(), port)
        try:
            if self.control:
                completed = threading.Event()
                outcome: dict[str, object] = {}

                def lookup() -> None:
                    try:
                        outcome["answers"] = socket.getaddrinfo(
                            host, port, type=socket.SOCK_STREAM,
                        )
                    except Exception as exc:
                        outcome["error"] = exc
                    finally:
                        completed.set()

                threading.Thread(target=lookup, daemon=True).start()
                while not completed.wait(min(0.1, self.control.timeout(1))):
                    self.control.check()
                if "error" in outcome:
                    raise outcome["error"]
                answers = outcome["answers"]
            else:
                answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(str(ipaddress.ip_address(a[4][0])) for a in answers))
            addresses.sort(key=lambda address: ipaddress.ip_address(address).version)
        except (socket.gaierror, UnicodeError, ValueError) as exc:
            raise InvalidTarget(f"Không phân giải được tên miền: {host}.") from exc
        if not addresses:
            raise InvalidTarget(f"Không phân giải được tên miền: {host}.")
        if not self.allow_private:
            allowed = all(
                ipaddress.ip_address(ip).is_loopback if is_loopback_host(host)
                else ipaddress.ip_address(ip).is_global
                for ip in addresses
            )
            if not allowed:
                error = "DNS trả về địa chỉ nội bộ hoặc thay đổi sang địa chỉ bị chặn."
                if key in self.addresses:
                    raise DNSChanged(error)
                raise InvalidTarget(error)
        if key in self.addresses:
            if self.addresses[key] not in addresses:
                raise DNSChanged("DNS của website đã thay đổi trong lúc quét; đã dừng kết nối.")
        else:
            self.addresses[key] = addresses[0]
        if self.control:
            self.control.check()
        return self.addresses[key]


class PinnedAdapter(HTTPAdapter):
    def __init__(self, dns: PinnedDNS):
        self.dns = dns
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        dns = self.dns

        class PinnedHTTPConnection(HTTPConnection):
            def _new_conn(self):
                original = self._dns_host
                try:
                    self._dns_host = dns.addresses[(original.lower(), self.port)]
                    return super()._new_conn()
                finally:
                    self._dns_host = original

        class PinnedHTTPSConnection(HTTPSConnection):
            def _new_conn(self):
                original = self._dns_host
                try:
                    self._dns_host = dns.addresses[(original.lower(), self.port)]
                    return super()._new_conn()
                finally:
                    self._dns_host = original

        class PinnedHTTPPool(HTTPConnectionPool):
            ConnectionCls = PinnedHTTPConnection

        class PinnedHTTPSPool(HTTPSConnectionPool):
            ConnectionCls = PinnedHTTPSConnection

        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": PinnedHTTPPool, "https": PinnedHTTPSPool,
        }

    def send(self, request, **kwargs):
        parsed = urlsplit(request.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.dns.verify(host, port)
        # Never allow caller-supplied proxy settings to route around pinned DNS.
        kwargs["proxies"] = {}
        return super().send(request, **kwargs)


def guarded_session(dns: PinnedDNS) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.websec_dns = dns
    if hasattr(session, "mount"):
        adapter = PinnedAdapter(dns)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session
