"""HTML-only content features. No JavaScript is executed."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from url_features import SUSPICIOUS_TERMS

PAGE_FEATURE_NAMES = [
    "html_length", "visible_text_length", "form_count", "password_input_count",
    "hidden_input_count", "input_count", "iframe_count", "script_count", "image_count",
    "anchor_count", "external_link_ratio", "external_form_action_count", "empty_form_action_count",
    "javascript_href_count", "meta_refresh_count", "on_event_handler_count", "suspicious_page_term_count",
    "has_password_form", "has_urgent_language", "title_length", "title_suspicious_term_count",
]

URGENT_TERMS = ("urgent", "immediately", "suspended", "limited", "expire", "action required", "verify now")


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _external(target: str, base_url: str) -> bool:
    if not target:
        return False
    absolute = urljoin(base_url, target)
    target_host = _host(absolute)
    base_host = _host(base_url)
    return bool(target_host and base_host and target_host != base_host)


def extract_page_features(html: str, page_url: str) -> dict[str, float]:
    """Extract signals from downloaded HTML. The function never fetches a URL."""
    soup = BeautifulSoup(html or "", "html.parser")
    visible_text = soup.get_text(" ", strip=True)
    lower_text = visible_text.lower()
    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    anchors = soup.find_all("a")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    external_links = sum(_external(a.get("href", ""), page_url) for a in anchors if a.get("href"))
    external_form_actions = sum(
        _external(form.get("action", ""), page_url) for form in forms if form.get("action")
    )
    empty_form_actions = sum(not (form.get("action") or "").strip() for form in forms)
    event_count = sum(1 for tag in soup.find_all(True) for key in tag.attrs if key.lower().startswith("on"))
    javascript_hrefs = sum((a.get("href") or "").strip().lower().startswith("javascript:") for a in anchors)
    password_inputs = sum((item.get("type") or "").lower() == "password" for item in inputs)
    hidden_inputs = sum((item.get("type") or "").lower() == "hidden" for item in inputs)
    suspicious_page_terms = sum(term in lower_text for term in SUSPICIOUS_TERMS)
    title_lower = title.lower()

    return {
        "html_length": float(min(len(html or ""), 1_000_000)),
        "visible_text_length": float(min(len(visible_text), 500_000)),
        "form_count": float(len(forms)),
        "password_input_count": float(password_inputs),
        "hidden_input_count": float(hidden_inputs),
        "input_count": float(len(inputs)),
        "iframe_count": float(len(soup.find_all("iframe"))),
        "script_count": float(len(soup.find_all("script"))),
        "image_count": float(len(soup.find_all("img"))),
        "anchor_count": float(len(anchors)),
        "external_link_ratio": round(float(external_links / len(anchors)), 6) if anchors else 0.0,
        "external_form_action_count": float(external_form_actions),
        "empty_form_action_count": float(empty_form_actions),
        "javascript_href_count": float(javascript_hrefs),
        "meta_refresh_count": float(sum(bool(tag.get("http-equiv")) and str(tag.get("http-equiv")).lower() == "refresh" for tag in soup.find_all("meta"))),
        "on_event_handler_count": float(event_count),
        "suspicious_page_term_count": float(suspicious_page_terms),
        "has_password_form": float(password_inputs > 0 and len(forms) > 0),
        "has_urgent_language": float(any(term in lower_text for term in URGENT_TERMS)),
        "title_length": float(len(title)),
        "title_suspicious_term_count": float(sum(term in title_lower for term in SUSPICIOUS_TERMS)),
    }
