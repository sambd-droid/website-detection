"""Streamlit app: safely fetch public HTML and classify phishing risk."""
from __future__ import annotations

from pathlib import Path

import joblib
import streamlit as st
from bs4 import BeautifulSoup

from model_features import make_feature_row
from page_features import extract_page_features
from safe_fetcher import UnsafeUrlError, fetch_html

BASE = Path(__file__).resolve().parent
MODEL_PATH = BASE / "models" / "live_page_phishing_model.joblib"

st.set_page_config(page_title="PhishGuard Live Inspector", page_icon="🛡️", layout="centered")


@st.cache_resource
def load_artifact() -> dict:
    return joblib.load(MODEL_PATH)


def risk_level(probability: float) -> tuple[str, str]:
    if probability >= 0.80:
        return "High", "Do not enter passwords, OTPs, card information, or personal data. Verify the domain independently."
    if probability >= 0.50:
        return "Medium", "The page has suspicious signals. Do not log in until you verify the official domain through a trusted source."
    if probability >= 0.20:
        return "Low", "The model found fewer phishing signals. This is not fully accuarte."
     return "Low", "The model found  good signals. This is not fully accuarte."


def page_title(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.title.get_text(" ", strip=True) if soup.title else "No page title detected"


def signal_list(page: dict[str, float]) -> list[str]:
    signals = []
    if page["password_input_count"]:
        signals.append(f"Password field detected ({int(page['password_input_count'])})")
    if page["external_form_action_count"]:
        signals.append("A form submits to a different domain")
    if page["iframe_count"]:
        signals.append(f"Embedded iframe detected ({int(page['iframe_count'])})")
    if page["has_urgent_language"]:
        signals.append("Urgent or account-pressure language detected")
    if page["meta_refresh_count"]:
        signals.append("Automatic page refresh/redirect detected")
    if page["javascript_href_count"]:
        signals.append("JavaScript-based link detected")
    return signals or ["No prominent page-content warning signal was detected."]


def main() -> None:
    st.title("🛡️ Live Website Phishing Detector")
    st.write("Enter a public website URL. The app safely retrieves its **HTML source** and the ML model analyses both the URL and page content.")
    st.caption("The app does not render the page, execute JavaScript, submit forms, click links, or access local/private addresses.")

    if not MODEL_PATH.exists():
        st.error("Model is missing. Run: python generate_demo_data.py && python train_model.py")
        st.stop()

    url = st.text_input("Website URL", placeholder="https://example.com")
    if st.button("Open and inspect website", type="primary", use_container_width=True):
        if not url.strip():
            st.error("Please enter a URL first.")
            return
        try:
            with st.spinner("Retrieving the public HTML safely and extracting page features..."):
                result = fetch_html(url)
                artifact = load_artifact()
                X = make_feature_row(result.final_url, result.html)
                probability = float(artifact["model"].predict_proba(X[artifact["feature_names"]])[:, 1][0])
                page = extract_page_features(result.html, result.final_url)
        except UnsafeUrlError as exc:
            st.error(f"The website was not inspected: {exc}")
            return
        except Exception:
            st.error("The page could not be analysed. Try a normal public HTML website.")
            return

        prediction = "PHISHING WEBSITE" if probability >= 0.50 else "LIKELY LEGITIMATE"
        level, advice = risk_level(probability)
        st.divider()
        st.subheader("Model reply")
        (st.error if probability >= 0.50 else st.success)(f"**{prediction}**")
        a, b, c = st.columns(3)
        a.metric("Phishing probability", f"{probability * 100:.1f}%")
        b.metric("Risk level", level)
        c.metric("HTTP status", result.status_code)
        st.info(advice)

        st.subheader("Website inspection summary")
        st.write(f"**Page title:** {page_title(result.html)}")
        st.write(f"**Final checked URL:** `{result.final_url}`")
        st.write(f"**Redirects followed:** {len(result.redirect_chain)}")
        st.write("**Signals found:**")
        for signal in signal_list(page):
            st.write(f"• {signal}")

        with st.expander("Technical features used by the model"):
            st.json({key: value for key, value in page.items() if value})
        with st.expander("Important limitation"):
            st.warning("The included model is trained on synthetic demonstration data. Train and evaluate it with verified phishing/legitimate URLs plus cached HTML before using its accuracy in a thesis or any security decision.")


if __name__ == "__main__":
    main()
