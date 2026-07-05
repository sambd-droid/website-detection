"""Feature assembly shared by training and live prediction."""
from __future__ import annotations

import pandas as pd

from page_features import PAGE_FEATURE_NAMES, extract_page_features
from url_features import URL_FEATURE_NAMES, extract_url_features

FEATURE_NAMES = URL_FEATURE_NAMES + PAGE_FEATURE_NAMES


def make_feature_row(url: str, html: str) -> pd.DataFrame:
    values = {**extract_url_features(url), **extract_page_features(html, url)}
    return pd.DataFrame([values], columns=FEATURE_NAMES).astype(float)
