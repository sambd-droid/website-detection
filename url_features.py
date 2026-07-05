"""Lexical features extracted locally from a URL."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlparse

SUSPICIOUS_TERMS = (
    "account", "auth", "bank", "billing", "confirm", "credential", "login", "password",
    "pay", "payment", "secure", "signin", "support", "unlock", "update", "validate",
    "verification", "verify", "wallet", "webscr",
)

URL_FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length", "count_dots",
    "count_hyphens", "count_underscores", "count_digits", "count_at", "count_question",
    "count_equals", "count_ampersand", "count_percent", "count_slashes", "subdomain_count",
    "tld_length", "uses_https", "has_ip_address", "has_port", "has_punycode",
    "suspicious_term_count", "url_entropy", "encoded_character_count", "double_slash_in_path",
]


def normalize_url(raw_url: object) -> str:
    text = str(raw_url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    return text


def hostname_from_url(raw_url: object) -> str:
    try:
        return (urlparse(normalize_url(raw_url)).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return float(-sum((v / len(value)) * math.log2(v / len(value)) for v in counts.values()))


def extract_url_features(raw_url: object) -> dict[str, float]:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = hostname_from_url(url)
    path = parsed.path or ""
    query = parsed.query or ""
    decoded = unquote(url).lower()
    labels = [x for x in host.split(".") if x]
    tld = labels[-1] if labels else ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    suspicious_count = sum(term in decoded for term in SUSPICIOUS_TERMS)

    return {
        "url_length": float(len(url)),
        "hostname_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "count_dots": float(url.count(".")),
        "count_hyphens": float(url.count("-")),
        "count_underscores": float(url.count("_")),
        "count_digits": float(sum(char.isdigit() for char in url)),
        "count_at": float(url.count("@")),
        "count_question": float(url.count("?")),
        "count_equals": float(url.count("=")),
        "count_ampersand": float(url.count("&")),
        "count_percent": float(url.count("%")),
        "count_slashes": float(url.count("/")),
        "subdomain_count": float(max(0, len(labels) - 2) if not is_ip_address(host) else 0),
        "tld_length": float(len(tld)),
        "uses_https": float(parsed.scheme.lower() == "https"),
        "has_ip_address": float(is_ip_address(host)),
        "has_port": float(port is not None),
        "has_punycode": float("xn--" in host),
        "suspicious_term_count": float(suspicious_count),
        "url_entropy": round(_entropy(url), 6),
        "encoded_character_count": float(url.lower().count("%")),
        "double_slash_in_path": float("//" in path),
    }
