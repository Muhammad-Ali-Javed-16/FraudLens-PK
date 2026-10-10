"""
Unit tests for the local rule-based detector (Stage 1).

All messages are fictional. Phone numbers and links are made up.
Run with:  python -m pytest -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import (  # noqa: E402
    ASSESSMENT_INSUFFICIENT,
    ASSESSMENT_SUSPICIOUS,
    ASSESSMENT_WARNING,
    MAX_MESSAGE_CHARS,
    analyze_message,
    defang,
)

# (name, message, expected assessment, rule ids that must be present)
SAMPLE_MESSAGES = [
    (
        "fake_prize",
        "Congratulations! You have won Rs 25,000 in the Mega Lucky Draw. Pay a "
        "registration fee of Rs 300 to claim your prize. Visit bit.ly/fake-win",
        ASSESSMENT_SUSPICIOUS,
        {"prize_claim", "upfront_payment", "shortened_url"},
    ),
    (
        "fake_wallet_verification",
        "JazzCash Alert: Your wallet will be suspended within 2 hours. Reply with "
        "your MPIN and CNIC number to verify your account.",
        ASSESSMENT_SUSPICIOUS,
        {"otp_request", "sensitive_info", "urgency_threat"},
    ),
    (
        "fake_delivery",
        "Pakistan Post: Your parcel is on hold due to an incomplete address. Pay "
        "delivery charges of Rs 150 at tinyurl.com/parcel-fake-pk immediately.",
        ASSESSMENT_SUSPICIOUS,
        {"upfront_payment", "shortened_url", "urgency_threat"},
    ),
    (
        "fake_job_fee",
        "You have been selected for a work-from-home data entry job. Salary 80,000 "
        "per month. Send Rs 2,000 registration fee on Easypaisa to confirm your seat.",
        ASSESSMENT_SUSPICIOUS,
        {"upfront_payment", "prize_claim"},
    ),
    (
        "roman_urdu_scam",
        "Mubarak ho! Aap ka number qurandazi mein jeet gaya hai. Inaam hasil karne "
        "ke liye apne number par aya code foran bata dein warna inaam cancel ho jayega.",
        ASSESSMENT_SUSPICIOUS,
        {"prize_claim", "otp_request", "urgency_threat"},
    ),
    (
        "university_reminder",
        "Reminder from the CS Department: The Data Structures quiz is on Monday at "
        "10 AM in Room 4. Please bring your student ID card. Check the LMS for the "
        "syllabus.",
        ASSESSMENT_INSUFFICIENT,
        set(),
    ),
]


@pytest.mark.parametrize(
    "name,message,expected,required_rules",
    SAMPLE_MESSAGES,
    ids=[m[0] for m in SAMPLE_MESSAGES],
)
def test_sample_messages(name, message, expected, required_rules):
    result = analyze_message(message)
    found = {i.rule_id for i in result.indicators}
    assert result.assessment == expected, f"{name}: got {result.assessment}, rules={found}"
    assert required_rules <= found, f"{name}: missing {required_rules - found}"


def test_evidence_is_exact_substring():
    """Every evidence phrase must be copied exactly from the message."""
    for _, message, _, _ in SAMPLE_MESSAGES:
        for indicator in analyze_message(message).indicators:
            for ev in indicator.evidence:
                assert message[ev.start : ev.end] == ev.phrase


def test_genuine_otp_notice_not_flagged_as_request():
    """A normal bank OTP SMS warns against sharing; it should not trigger otp_request."""
    msg = "Your OTP for login is 482913. Do not share this code with anyone."
    found = {i.rule_id for i in analyze_message(msg).indicators}
    assert "otp_request" not in found


def test_roman_urdu_prize_phrases():
    msg = "Aap ka number qurandazi mein jeet gaya hai"
    phrases = [e.phrase for i in analyze_message(msg).indicators for e in i.evidence]
    assert "qurandazi" in phrases
    assert "jeet gaya" in phrases


def test_urdu_script_detection():
    msg = "مبارک ہو! آپ نے انعام جیت لیا ہے۔ رجسٹریشن فیس فوری بھیجیں ورنہ انعام منسوخ ہو جائے گا۔"
    result = analyze_message(msg)
    found = {i.rule_id for i in result.indicators}
    assert {"prize_claim", "upfront_payment", "urgency_threat"} <= found
    assert result.assessment == ASSESSMENT_SUSPICIOUS


def test_single_medium_indicator_is_only_warning():
    result = analyze_message("Please reply urgently.")
    assert result.assessment == ASSESSMENT_WARNING


def test_empty_message():
    result = analyze_message("")
    assert result.assessment == ASSESSMENT_INSUFFICIENT
    assert result.indicators == []


def test_long_message_is_truncated():
    result = analyze_message("a" * (MAX_MESSAGE_CHARS + 10))
    assert result.truncated


def test_non_string_rejected():
    with pytest.raises(TypeError):
        analyze_message(None)


def test_url_trailing_punctuation_removed():
    result = analyze_message("Check bit.ly/abc123.")
    phrases = [e.phrase for i in result.indicators for e in i.evidence]
    assert "bit.ly/abc123" in phrases


def test_normal_link_not_flagged_as_shortened():
    found = {i.rule_id for i in analyze_message("See https://www.example.edu.pk/notice").indicators}
    assert "shortened_url" not in found


def test_defang_makes_links_non_clickable():
    assert defang("https://bit.ly/x") == "hxxps://bit[.]ly/x"
