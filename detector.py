"""
detector.py - FraudLens PK local warning-indicator engine.

This module is fully offline and rule-based. Each rule looks for a specific,
explainable warning sign (for example "asks you to share your OTP") in
English, Roman Urdu, or Urdu script, and records the exact phrase from the
message that triggered it.

Important: these rules find *potential warning indicators*. They do not prove
that a message is a scam, and finding nothing does not prove it is safe.

Security notes:
- The submitted message is treated as untrusted data. It is only searched
  with regular expressions; it is never executed, evaluated, or fetched.
- Links found in the message are never opened or visited.
- Nothing is stored or logged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Longer inputs are truncated to keep regex work small and predictable.
MAX_MESSAGE_CHARS = 5000

# How strongly each indicator contributes to the overall assessment.
SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1}

# Assessment thresholds (sum of severity weights).
SUSPICIOUS_THRESHOLD = 5  # e.g. one high + one medium indicator
WARNING_THRESHOLD = 2  # at least one medium or high indicator

ASSESSMENT_SUSPICIOUS = "Suspicious"
ASSESSMENT_WARNING = "Some Warning Signs"
ASSESSMENT_INSUFFICIENT = "Insufficient Evidence"

ASSESSMENT_LABELS = {
    ASSESSMENT_SUSPICIOUS: {"en": "Suspicious", "ur": "مشکوک"},
    ASSESSMENT_WARNING: {"en": "Some Warning Signs", "ur": "کچھ انتباہی علامات"},
    ASSESSMENT_INSUFFICIENT: {"en": "Insufficient Evidence", "ur": "ناکافی شواہد"},
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """An exact substring of the submitted message: message[start:end] == phrase."""

    phrase: str
    start: int
    end: int


@dataclass
class Indicator:
    """One warning rule that matched, plus the evidence that triggered it."""

    rule_id: str
    severity: str
    evidence: list[Evidence]


@dataclass
class AnalysisResult:
    assessment: str
    score: int
    indicators: list[Indicator] = field(default_factory=list)
    truncated: bool = False


# ---------------------------------------------------------------------------
# Human-readable rule descriptions (English + Urdu)
# ---------------------------------------------------------------------------

RULE_INFO: dict[str, dict] = {
    "otp_request": {
        "severity": "high",
        "title": {
            "en": "Asks for an OTP, PIN or verification code",
            "ur": "او ٹی پی، پن یا تصدیقی کوڈ مانگا گیا ہے",
        },
        "why": {
            "en": "Banks, wallets and telecom companies do not ask you to share OTPs "
            "or PINs. Anyone with your code can take over your account.",
            "ur": "بینک، موبائل والٹ اور ٹیلی کام کمپنیاں کبھی آپ سے او ٹی پی یا پن شیئر "
            "کرنے کو نہیں کہتیں۔ جس کے پاس آپ کا کوڈ ہو وہ آپ کا اکاؤنٹ استعمال کر سکتا ہے۔",
        },
        "advice": {
            "en": "Never share an OTP or PIN with anyone, even if they claim to be "
            "from your bank.",
            "ur": "اپنا او ٹی پی یا پن کسی کو نہ بتائیں، چاہے وہ خود کو بینک کا نمائندہ ہی کیوں نہ کہے۔",
        },
    },
    "sensitive_info": {
        "severity": "high",
        "title": {
            "en": "Asks for sensitive personal or financial details",
            "ur": "حساس ذاتی یا مالی معلومات مانگی گئی ہیں",
        },
        "why": {
            "en": "Requests for CNIC, card, account or password details through a "
            "message are a common way to steal identities and money.",
            "ur": "پیغام کے ذریعے شناختی کارڈ، کارڈ، اکاؤنٹ یا پاس ورڈ کی تفصیلات مانگنا "
            "شناخت اور رقم چرانے کا عام طریقہ ہے۔",
        },
        "advice": {
            "en": "Do not send personal details by SMS, WhatsApp or email. Contact "
            "the organization through its official number or website.",
            "ur": "ذاتی تفصیلات ایس ایم ایس، واٹس ایپ یا ای میل پر نہ بھیجیں۔ ادارے سے اس کے "
            "سرکاری نمبر یا ویب سائٹ کے ذریعے رابطہ کریں۔",
        },
    },
    "upfront_payment": {
        "severity": "high",
        "title": {
            "en": "Asks for an upfront payment or fee",
            "ur": "پیشگی رقم یا فیس مانگی گئی ہے",
        },
        "why": {
            "en": "Genuine prizes, jobs and deliveries rarely require you to pay a "
            "fee first. Advance-fee requests are a classic scam pattern.",
            "ur": "اصل انعام، نوکری یا پارسل کے لیے عموماً پہلے فیس ادا نہیں کرنی پڑتی۔ "
            "پیشگی رقم مانگنا فراڈ کا ایک عام طریقہ ہے۔",
        },
        "advice": {
            "en": "Do not send money to claim a prize, job or parcel. Verify "
            "independently before any payment.",
            "ur": "انعام، نوکری یا پارسل کے لیے رقم نہ بھیجیں۔ ادائیگی سے پہلے خود تصدیق کریں۔",
        },
    },
    "urgency_threat": {
        "severity": "medium",
        "title": {
            "en": "Uses urgent or threatening language",
            "ur": "جلد بازی یا دھمکی آمیز زبان استعمال کی گئی ہے",
        },
        "why": {
            "en": "Pressure such as short deadlines or threats of blocking is used "
            "to stop you from thinking or checking.",
            "ur": "ڈیڈ لائن یا اکاؤنٹ بند کرنے کی دھمکی جیسا دباؤ اس لیے ڈالا جاتا ہے تاکہ "
            "آپ سوچے یا تصدیق کیے بغیر عمل کریں۔",
        },
        "advice": {
            "en": "Slow down. Real organizations give you time and official ways to check.",
            "ur": "جلدی نہ کریں۔ اصل ادارے آپ کو وقت اور تصدیق کے سرکاری ذرائع دیتے ہیں۔",
        },
    },
    "prize_claim": {
        "severity": "medium",
        "title": {
            "en": "Claims you have won a prize or reward",
            "ur": "انعام یا تحفہ جیتنے کا دعویٰ کیا گیا ہے",
        },
        "why": {
            "en": "Unexpected prize or lucky-draw messages, especially for contests "
            "you never entered, are often used as bait.",
            "ur": "اچانک انعام یا قرعہ اندازی کے پیغامات، خاص طور پر ایسے مقابلوں کے جن میں "
            "آپ نے حصہ ہی نہیں لیا، اکثر دھوکہ دینے کے لیے بھیجے جاتے ہیں۔",
        },
        "advice": {
            "en": "Ignore prize claims you cannot confirm on the organization's "
            "official website or helpline.",
            "ur": "جس انعام کی تصدیق ادارے کی سرکاری ویب سائٹ یا ہیلپ لائن سے نہ ہو سکے، اسے نظر انداز کریں۔",
        },
    },
    "shortened_url": {
        "severity": "medium",
        "title": {
            "en": "Contains a shortened link",
            "ur": "مختصر کیا گیا لنک موجود ہے",
        },
        "why": {
            "en": "Link shorteners hide the real destination, which may be a fake "
            "login or payment page.",
            "ur": "مختصر لنک اصل ویب سائٹ کو چھپا دیتے ہیں، جو جعلی لاگ اِن یا ادائیگی کا صفحہ ہو سکتا ہے۔",
        },
        "advice": {
            "en": "Do not open the link. Type the official website address yourself instead.",
            "ur": "یہ لنک نہ کھولیں۔ اس کے بجائے ادارے کی سرکاری ویب سائٹ کا پتہ خود لکھیں۔",
        },
    },
    "brand_mention": {
        "severity": "low",
        "title": {
            "en": "Mentions a well-known organization",
            "ur": "کسی معروف ادارے کا نام لیا گیا ہے",
        },
        "why": {
            "en": "This alone is not suspicious, but scammers often impersonate "
            "banks, wallets, couriers and government programs.",
            "ur": "صرف یہ بات مشکوک نہیں، لیکن فراڈ کرنے والے اکثر بینک، موبائل والٹ، کوریئر "
            "اور سرکاری پروگراموں کا نام استعمال کرتے ہیں۔",
        },
        "advice": {
            "en": "Verify through the organization's official app, website or "
            "helpline, not the contact details in this message.",
            "ur": "اس پیغام میں دیے گئے نمبر کے بجائے ادارے کی سرکاری ایپ، ویب سائٹ یا ہیلپ لائن سے تصدیق کریں۔",
        },
    },
}


# ---------------------------------------------------------------------------
# Pattern lists. Each list mixes English, Roman Urdu and Urdu script.
# Python's `re` treats Urdu letters as word characters, so \w works for them.
# ---------------------------------------------------------------------------


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# Words meaning "share / send / tell / give" - used to detect a *request*.
REQUEST_VERBS = _compile(
    [
        r"\b(?:share|send|tell|provide|give|forward|reply\s+with)\b",
        r"\b(?:bata\w*|bhej\w*|de\s?d[eoi]\w*|likh\s?\w*)\b",  # Roman Urdu
        r"بتا\w*|بھیج\w*|شیئر|دے\s?د\w*|لکھ\w*",  # Urdu
    ]
)

# Extra verbs that commonly accompany requests for personal details.
DETAIL_VERBS = _compile(
    [
        r"\b(?:verify|update|submit|confirm)\b",
        r"\b(?:verify|update|confirm)\s?kar\w*\b",
        r"تصدیق|اپڈیٹ",
    ]
)

# Phrases that show the message is *warning against* sharing, e.g. a genuine
# bank OTP SMS: "Do not share this OTP with anyone."
NEGATIONS = _compile(
    [
        r"\bdo\s*not\b|\bdon'?t\b|\bnever\b",
        r"\bkisi\s+(?:ko|se)\b|\bmat\b",  # Roman Urdu
        r"کسی\s?کو|مت\b|نہ\s?بتا",  # Urdu
    ]
)

OTP_TERMS = _compile(
    [
        r"\bo\.?t\.?p\b",
        r"\bone[\s-]?time[\s-]?(?:password|pin|code)\b",
        r"\b(?:atm\s|card\s|secret\s)?m?pin\b(?:\s?(?:code|number))?",
        r"\bcvv\b",
        r"\b(?:verification|security|confirmation|activation|\d[\s-]?digit)\s?code\b",
        r"\bcode\b",
        r"او\s?ٹی\s?پی|کوڈ|خفیہ\s?نمبر",
    ]
)

SENSITIVE_TERMS = _compile(
    [
        r"\bcnic\b",
        r"\b(?:id|identity)\s?card(?:\s?(?:number|no\.?))?",
        r"\b(?:bank\s)?account\s?(?:number|no\.?|details)\b",
        r"\b(?:debit|credit|atm)\s?card(?:\s?(?:number|no\.?|details))?",
        r"\bcard\s?(?:number|no\.?|details)\b",
        r"\bpassword\b",
        r"\bdate\s?of\s?birth\b",
        r"\bmother'?s\s?(?:maiden\s)?name\b",
        r"\b(?:personal|bank|login|account)\s?(?:details|information|info)\b",
        r"\biban\b",
        r"\bshanakhti\s?card\b",
        r"\bapn[ai]\s?(?:details|tafseelat|maloomat)\b",
        r"شناختی\s?کارڈ|اکاؤنٹ\s?نمبر|پاس\s?ورڈ|کارڈ\s?نمبر|ذاتی\s?معلومات",
    ]
)

PAYMENT_PATTERNS = _compile(
    [
        r"\b(?:registration|processing|activation|verification|clearance|customs|"
        r"delivery|handling|service|security)\s?(?:fee|fees|charges?|deposit)\b",
        r"\badvance\s?(?:payment|fee|amount)\b",
        r"\b(?:pay|send|transfer|deposit)\b[^.\n]{0,25}?(?:rs\.?|pkr|rupees)\s?\d[\d,]*",
        r"\b(?:pay|send|transfer|deposit)\b[^.\n]{0,25}?\d[\d,]*\s?(?:rs|pkr|rupees)\b",
        r"\bfee?s?\s?(?:jama|ada)\s?kar\w*",  # Roman Urdu
        r"\b(?:paise|paisay|raqam|amount|rupay|rupees)\s?(?:bhej\w*|jama\w*|transfer\w*)",
        r"\b(?:easy\s?paisa|jazz\s?cash)\s?(?:pe|par|mein|me|se)?\s?(?:bhej\w*|send|transfer\w*|jama\w*)",
        r"رجسٹریشن\s?فیس|فیس\s?(?:جمع|ادا)|رقم\s?(?:بھیج|جمع|ٹرانسفر)\w*|ایڈوانس\s?(?:رقم|ادائیگی|فیس)",
    ]
)

URGENCY_PATTERNS = _compile(
    [
        r"\burgent(?:ly)?\b",
        r"\bimmediately\b",
        r"\bwithin\s\d+\s?(?:hours?|hrs?|minutes?|mins?|days?)\b",
        r"\b(?:account|sim|number|card|wallet)\b[^.\n]{0,30}?\b(?:blocked|suspended|"
        r"closed|deactivated|disabled|terminated)\b",
        r"\blast\s(?:chance|warning)\b",
        r"\bfinal\s(?:warning|notice)\b",
        r"\bact\snow\b",
        r"\blegal\saction\b",
        r"\b(?:expires?|expiring)\s(?:today|tonight|soon)\b",
        r"\bfor(?:an|i|ee)\b",  # Roman Urdu
        r"\bjald(?:i|\s?az\s?jald)\b",
        r"\b(?:band|bund|block)\s?(?:ho|kar)\s?(?:jaye?ga|jayegi|diya\s?jaye?ga|denge)\b",
        r"\bwarna\b",
        r"\b(?:aakhri|akhri)\s?(?:mauqa|moqa|mouqa)\b",
        r"فوری|فوراً|فورا|بند\s?(?:ہو|کر)\s?(?:جائے|دیا)\w*|بلاک|ورنہ|آخری\s?موقع|قانونی\s?کارروائی",
    ]
)

PRIZE_PATTERNS = _compile(
    [
        r"\bcongratulations?\b|\bcongrats\b",
        r"\byou(?:'ve|\shave)?\s(?:won|been\sselected)\b",
        r"\bwinner\b",
        r"\blucky\s(?:draw|winner|number|customer)\b",
        r"\b(?:cash\s)?prize\b",
        r"\bjackpot\b",
        r"\bclaim\s(?:your|the)\s(?:prize|reward|gift|amount)\b",
        r"\bfree\s(?:iphone|gift|laptop|bike|car|recharge)\b",
        r"\bina+m\b",  # Roman Urdu
        r"\bmubarak\s?ho\b",
        r"\bqur(?:a|e|'a)?\s?andazi\b",
        r"\bjeet\s?(?:ga(?:ya|ye|yi|e)|liya|chuke)\b",
        r"انعام|مبارک\s?ہو|قرعہ\s?اندازی|جیت\s?(?:لیا|گئے|چکے)",
    ]
)

BRAND_PATTERNS = _compile(
    [
        r"\b(?:jazz\s?cash|easy\s?paisa|hbl|ubl|mcb|meezan|allied\s?bank|bank\s?alfalah|"
        r"state\s?bank|sbp|fbr|pta|nadra|bisp|benazir\s?income|ehsaas|tcs|leopards|"
        r"pakistan\s?post|daraz|telenor|zong|ufone|jazz)\b",
        r"بینظیر|احساس|نادرا|جاز\s?کیش|ایزی\s?پیسہ",
    ]
)

# Common public link-shortening services. Matched against the link's host name.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly", "s.id", "t.ly", "v.gd",
    "buff.ly", "lnkd.in", "shorte.st", "bl.ink", "short.io", "tiny.one",
}

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"']*",
    re.IGNORECASE,
)

_TRAILING_PUNCTUATION = ".,;:!?)]}'\"،۔"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

Span = tuple[int, int]


def _find_all(text: str, patterns: list[re.Pattern]) -> list[Span]:
    """Return (start, end) spans for every non-empty match of every pattern."""
    spans = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            if match.end() > match.start():
                spans.append((match.start(), match.end()))
    return spans


def _merge_spans(spans: list[Span]) -> list[Span]:
    """Merge overlapping spans so the same text is not reported twice."""
    merged: list[Span] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _to_evidence(text: str, spans: list[Span]) -> list[Evidence]:
    return [Evidence(text[s:e], s, e) for s, e in _merge_spans(spans)]


def _is_negated(text: str, start: int, end: int, window: int = 30) -> bool:
    """True if a negation word ("do not", "never", "kisi ko") is near the span."""
    context = text[max(0, start - window) : end + window]
    return any(p.search(context) for p in NEGATIONS)


def _find_requests(
    text: str,
    term_patterns: list[re.Pattern],
    verb_patterns: list[re.Pattern],
    window: int = 40,
) -> list[Span]:
    """
    Find places where a sensitive term (e.g. "OTP") appears close to a request
    verb (e.g. "share", "bata dein"). The evidence span covers both words.
    Terms that are clearly negated ("do not share your OTP") are skipped.
    """
    terms = _find_all(text, term_patterns)
    verbs = _find_all(text, verb_patterns)
    spans = []
    for t_start, t_end in terms:
        if _is_negated(text, t_start, t_end):
            continue
        nearby = [
            (v_start, v_end)
            for v_start, v_end in verbs
            if v_start < t_end + window and v_end > t_start - window
        ]
        if nearby:
            v_start, v_end = min(nearby, key=lambda v: abs(v[0] - t_start))
            spans.append((min(t_start, v_start), max(t_end, v_end)))
    return spans


def _clean_url_span(text: str, start: int, end: int) -> Span:
    """Drop trailing punctuation such as the full stop at the end of a sentence."""
    while end > start and text[end - 1] in _TRAILING_PUNCTUATION:
        end -= 1
    return start, end


def _url_host(url: str) -> str:
    """Extract the lowercase host name from a URL string without contacting it."""
    host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
    host = re.split(r"[/?#:]", host, maxsplit=1)[0].lower()
    return host[4:] if host.startswith("www.") else host


# ---------------------------------------------------------------------------
# Individual detection rules (each returns a list of evidence spans)
# ---------------------------------------------------------------------------


def detect_otp_request(text: str) -> list[Span]:
    """Message asks the reader to share an OTP, PIN or verification code."""
    return _find_requests(text, OTP_TERMS, REQUEST_VERBS)


def detect_sensitive_info_request(text: str) -> list[Span]:
    """Message asks for CNIC, card, account, password or similar details."""
    return _find_requests(text, SENSITIVE_TERMS, REQUEST_VERBS + DETAIL_VERBS)


def detect_upfront_payment(text: str) -> list[Span]:
    """Message asks for a fee or payment before something is delivered."""
    return _find_all(text, PAYMENT_PATTERNS)


def detect_urgency_threat(text: str) -> list[Span]:
    """Message uses deadlines, pressure, or threats of blocking/legal action."""
    return _find_all(text, URGENCY_PATTERNS)


def detect_prize_claim(text: str) -> list[Span]:
    """Message claims the reader won a prize, lucky draw, or reward."""
    return _find_all(text, PRIZE_PATTERNS)


def detect_shortened_url(text: str) -> list[Span]:
    """Message contains a link from a known URL-shortening service."""
    spans = []
    for match in URL_PATTERN.finditer(text):
        start, end = _clean_url_span(text, match.start(), match.end())
        if _url_host(text[start:end]) in URL_SHORTENERS:
            spans.append((start, end))
    return spans


def detect_brand_mention(text: str) -> list[Span]:
    """Message names a bank, wallet, courier or government program."""
    return _find_all(text, BRAND_PATTERNS)


RULES = {
    "otp_request": detect_otp_request,
    "sensitive_info": detect_sensitive_info_request,
    "upfront_payment": detect_upfront_payment,
    "urgency_threat": detect_urgency_threat,
    "prize_claim": detect_prize_claim,
    "shortened_url": detect_shortened_url,
    "brand_mention": detect_brand_mention,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assess(score: int) -> str:
    """Convert a total indicator score into one of three advisory labels."""
    if score >= SUSPICIOUS_THRESHOLD:
        return ASSESSMENT_SUSPICIOUS
    if score >= WARNING_THRESHOLD:
        return ASSESSMENT_WARNING
    return ASSESSMENT_INSUFFICIENT


def analyze_message(message: str) -> AnalysisResult:
    """
    Run every rule on the message and combine the results.

    The returned evidence phrases are exact substrings of the (possibly
    truncated) message, so they can be shown to the user as proof.
    """
    if not isinstance(message, str):
        raise TypeError("message must be a string")

    truncated = len(message) > MAX_MESSAGE_CHARS
    text = message[:MAX_MESSAGE_CHARS]

    indicators = []
    for rule_id, rule in RULES.items():
        evidence = _to_evidence(text, rule(text))
        if evidence:
            indicators.append(Indicator(rule_id, RULE_INFO[rule_id]["severity"], evidence))

    score = sum(SEVERITY_WEIGHTS[i.severity] for i in indicators)
    return AnalysisResult(assess(score), score, indicators, truncated)


def defang(text: str) -> str:
    """
    Make links non-clickable for display, e.g. "https://bit.ly/x" becomes
    "hxxps://bit[.]ly/x". This is a common security practice when showing
    suspicious links.
    """

    def _defang_url(match: re.Match) -> str:
        url = match.group(0)
        url = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
        return url.replace(".", "[.]")

    return URL_PATTERN.sub(_defang_url, text)
