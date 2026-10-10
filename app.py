"""
app.py - FraudLens PK Streamlit interface.

Run with:  streamlit run app.py

Privacy: messages are analyzed in memory only. Nothing is saved, logged,
or sent anywhere in Stage 1. Links inside messages are never opened.
"""

from __future__ import annotations

import html

import streamlit as st

from ai_engine import get_ai_status
from detector import (
    ASSESSMENT_INSUFFICIENT,
    ASSESSMENT_LABELS,
    ASSESSMENT_SUSPICIOUS,
    ASSESSMENT_WARNING,
    MAX_MESSAGE_CHARS,
    RULE_INFO,
    analyze_message,
    defang,
)

# ---------------------------------------------------------------------------
# Fictional example messages (all numbers and links are made up)
# ---------------------------------------------------------------------------

EXAMPLES = {
    "Fake prize": (
        "Congratulations! Your number has won Rs 50,000 in the Mega Lucky Draw. "
        "To claim your prize, pay a processing fee of Rs 500 via JazzCash to "
        "0300-0000000 within 24 hours. Details: bit.ly/example-prize"
    ),
    "Fake wallet alert": (
        "Dear customer, your Easypaisa account will be blocked today. Share the "
        "6-digit verification code we sent you immediately to keep it active."
    ),
    "Roman Urdu scam": (
        "Mubarak ho! Aap ka naam BISP qurandazi mein aya hai. Raqam hasil karne "
        "ke liye apna CNIC number aur code foran bata dein warna inaam cancel "
        "ho jayega."
    ),
}

SEVERITY_BADGE = {
    "high": {"en": "🔴 High concern", "ur": "🔴 زیادہ تشویش"},
    "medium": {"en": "🟠 Medium concern", "ur": "🟠 درمیانی تشویش"},
    "low": {"en": "🟡 Low concern", "ur": "🟡 کم تشویش"},
}

TEXT = {
    "evidence": {"en": "Exact phrase(s) from the message:", "ur": "پیغام سے اصل الفاظ:"},
    "why": {"en": "Why this may be concerning:", "ur": "یہ کیوں تشویشناک ہو سکتا ہے:"},
    "steps": {"en": "Safe next steps", "ur": "محفوظ اقدامات"},
    "indicators": {"en": "Warning indicators found", "ur": "پائی گئی انتباہی علامات"},
    "none_found": {
        "en": "No rule-based warning indicators were found. This does NOT mean "
        "the message is safe. New scams may use wording these rules do not cover.",
        "ur": "کوئی انتباہی علامت نہیں ملی۔ اس کا مطلب یہ نہیں کہ پیغام محفوظ ہے۔ "
        "نئے فراڈ ایسے الفاظ استعمال کر سکتے ہیں جو ان اصولوں میں شامل نہیں۔",
    },
    "disclaimer": {
        "en": "FraudLens PK is an educational, advisory tool. It cannot verify who "
        "sent a message and may be wrong. Always confirm through the "
        "organization's official website, app, or helpline.",
        "ur": "فراڈ لینز پی کے ایک تعلیمی اور مشاورتی ٹول ہے۔ یہ پیغام بھیجنے والے کی "
        "تصدیق نہیں کر سکتا اور غلط بھی ہو سکتا ہے۔ ہمیشہ ادارے کی سرکاری ویب سائٹ، "
        "ایپ یا ہیلپ لائن سے تصدیق کریں۔",
    },
}

GENERAL_ADVICE = [
    {
        "en": "Do not click links or call numbers given in a suspicious message.",
        "ur": "مشکوک پیغام میں دیے گئے لنک نہ کھولیں اور نمبروں پر کال نہ کریں۔",
    },
    {
        "en": "If you already shared a code, details, or money, contact your bank "
        "or wallet through its official helpline right away.",
        "ur": "اگر آپ کوڈ، تفصیلات یا رقم دے چکے ہیں تو فوراً اپنے بینک یا والٹ کی "
        "سرکاری ہیلپ لائن سے رابطہ کریں۔",
    },
]


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def show_text(text: str, lang: str, bold: bool = False) -> None:
    """
    Render our own explanation text. Urdu is shown right-to-left.
    Text is HTML-escaped first, so this is safe even with unsafe_allow_html.
    """
    safe = html.escape(text)
    if bold:
        safe = f"<strong>{safe}</strong>"
    if lang == "ur":
        st.markdown(
            f'<div dir="rtl" style="text-align:right;font-size:1.1rem;'
            f'line-height:1.9">{safe}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(f"<div>{safe}</div>", unsafe_allow_html=True)


def show_evidence(phrase: str) -> None:
    """
    Show an untrusted phrase from the message as plain, non-clickable text.
    st.code never renders Markdown/HTML, and links are defanged.
    """
    st.code(defang(phrase), language=None, wrap_lines=True)


def set_example(name: str) -> None:
    st.session_state.message = EXAMPLES[name]


def show_assessment(assessment: str, lang: str) -> None:
    label = ASSESSMENT_LABELS[assessment]["en"]
    if lang == "ur":
        label = f'{label} · {ASSESSMENT_LABELS[assessment]["ur"]}'
    banner = {
        ASSESSMENT_SUSPICIOUS: st.error,
        ASSESSMENT_WARNING: st.warning,
        ASSESSMENT_INSUFFICIENT: st.info,
    }[assessment]
    banner(f"**Assessment: {label}**")


def render_results(message: str, lang: str) -> None:
    result = analyze_message(message)

    st.divider()
    show_assessment(result.assessment, lang)

    if result.truncated:
        st.caption(f"Only the first {MAX_MESSAGE_CHARS} characters were analyzed.")

    if not result.indicators:
        show_text(TEXT["none_found"][lang], lang)
    else:
        st.subheader(TEXT["indicators"]["en"])
        if lang == "ur":
            show_text(TEXT["indicators"]["ur"], lang, bold=True)

        for indicator in result.indicators:
            info = RULE_INFO[indicator.rule_id]
            with st.container(border=True):
                show_text(info["title"][lang], lang, bold=True)
                st.caption(SEVERITY_BADGE[indicator.severity][lang])
                show_text(TEXT["evidence"][lang], lang)
                for ev in indicator.evidence:
                    show_evidence(ev.phrase)
                show_text(TEXT["why"][lang] + " " + info["why"][lang], lang)

    # Safe next steps: advice from each matched rule, then general advice.
    st.subheader(TEXT["steps"]["en"])
    if lang == "ur":
        show_text(TEXT["steps"]["ur"], lang, bold=True)
    advice = [RULE_INFO[i.rule_id]["advice"][lang] for i in result.indicators]
    advice += [a[lang] for a in GENERAL_ADVICE]
    for item in dict.fromkeys(advice):  # remove duplicates, keep order
        show_text("• " + item, lang)

    st.divider()
    show_text(TEXT["disclaimer"][lang], lang)


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

st.set_page_config(page_title="FraudLens PK", page_icon="🔍", layout="centered")

st.title("🔍 FraudLens PK")
st.markdown(
    "**An explainable scam-awareness assistant for Pakistan.** Paste a suspicious "
    "SMS, WhatsApp message, email, or online offer in English, Urdu, or Roman Urdu. "
    "FraudLens PK points out possible warning signs, shows the exact words that "
    "triggered them, and suggests safer next steps."
)
st.caption(
    "Educational tool only. Not a verified fraud-detection service. "
    "Your message is not stored, and links in it are never opened."
)

ai_status = get_ai_status()
if not ai_status.configured:
    st.warning(f"⚙️ {ai_status.message}")

st.markdown("**Try a fictional example:**")
cols = st.columns(len(EXAMPLES))
for col, name in zip(cols, EXAMPLES):
    col.button(name, on_click=set_example, args=(name,), use_container_width=True)

st.text_area(
    "Message to check",
    key="message",
    height=180,
    max_chars=MAX_MESSAGE_CHARS,
    placeholder="Paste the message here...",
)

language = st.radio(
    "Explanation language",
    options=["en", "ur"],
    format_func=lambda code: "English" if code == "en" else "اردو (Urdu)",
    horizontal=True,
)

if st.button("Analyze Message", type="primary", use_container_width=True):
    message = st.session_state.get("message", "").strip()
    if not message:
        st.warning("Please paste a message first.")
    else:
        render_results(message, language)
