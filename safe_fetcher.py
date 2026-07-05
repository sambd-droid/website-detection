"""Constrained HTML retrieval for defensive URL inspection.

The fetcher blocks localhost/private/reserved networks, non-web schemes, non-standard
ports, follows a limited redirect chain, and does not execute page JavaScript.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests

from url_features import normalize_url

MAX_REDIRECTS = 4
MAX_BYTES = 1_000_000
ALLOWED_PORTS = {80, 443}
USER_AGENT = "PhishGuard-Defensive-Research/1.0 (+local HTML inspection)"


class UnsafeUrlError(ValueError):
    """Raised when an entered URL is unsafe for the server to retrieve."""


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    html: str
    status_code: int
    title: str
    redirect_chain: list[str]
    content_type: str


def _resolve(hostname: str, port: int) -> set[str]:
    try:
        rows = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Could not resolve hostname: {hostname}") from exc
    return {row[4][0] for row in rows}


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return bool(ip.is_global)


def validate_fetch_url(raw_url: str) -> str:
    """Validate URL and DNS destinations before every outbound request."""
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeUrlError("Only http:// and https:// URLs can be inspected.")
    if not parsed.hostname:
        raise UnsafeUrlError("A hostname is required.")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("URLs with embedded credentials are not allowed.")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise UnsafeUrlError("The URL contains an invalid port.") from exc
    if port not in ALLOWED_PORTS:
        raise UnsafeUrlError("Only standard web ports 80 and 443 are allowed.")

    addresses = _resolve(parsed.hostname, port)
    if not addresses or any(not _is_public_ip(addr) for addr in addresses):
        raise UnsafeUrlError("The hostname resolves to a private, local, or reserved network and is blocked.")
    return url


def _read_limited(response: requests.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_BYTES:
            raise UnsafeUrlError(f"Page is larger than {MAX_BYTES:,} bytes and was not inspected.")
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_html(raw_url: str) -> FetchResult:
    """Download a small HTML page after validating each redirect target."""
    current = validate_fetch_url(raw_url)
    redirect_chain: list[str] = []
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})

    try:
        for redirect_number in range(MAX_REDIRECTS + 1):
            response = session.get(current, timeout=(4, 10), allow_redirects=False, stream=True, verify=True)
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise UnsafeUrlError("Redirect response did not include a destination.")
                if redirect_number >= MAX_REDIRECTS:
                    raise UnsafeUrlError(f"Too many redirects (maximum {MAX_REDIRECTS}).")
                redirect_chain.append(current)
                current = validate_fetch_url(urljoin(current, location))
                continue

            content_type = response.headers.get("Content-Type", "").lower()
            if "html" not in content_type and "xhtml" not in content_type:
                response.close()
                raise UnsafeUrlError(f"Only HTML pages are supported; received {content_type or 'unknown content type'}.")
            raw = _read_limited(response)
            response.close()
            encoding = response.encoding or "utf-8"
            html = raw.decode(encoding, errors="replace")
            return FetchResult(
                requested_url=normalize_url(raw_url),
                final_url=current,
                html=html,
                status_code=response.status_code,
                title="",
                redirect_chain=redirect_chain,
                content_type=content_type,
            )
    except requests.RequestException as exc:
        raise UnsafeUrlError(f"Website could not be retrieved safely: {exc.__class__.__name__}") from exc
    finally:
        session.close()

    raise UnsafeUrlError(f"Too many redirects (maximum {MAX_REDIRECTS}).")
