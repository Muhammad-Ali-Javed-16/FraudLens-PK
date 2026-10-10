# FraudLens PK

An explainable, multilingual scam-awareness assistant for Pakistani users. Built for Hacktoberfest Islamabad 2026.

> Educational and advisory only. FraudLens PK cannot verify who sent a message and may be wrong.

## Status

| Stage | Description | Status |
|---|---|---|
| 1 | Streamlit UI + local rule-based detector | Done |
| 2 | Verified open-weight model (≤ 8B) integration | Not started |
| 3 | Structured AI analysis + evidence validation | Not started |
| 4 | Testing, UI polish, documented findings | Not started |
| 5 | Submission + demo | Not started |

**No AI model is connected yet.** The app currently uses only the local detector and shows a setup notice.

## Problem and Solution

Pakistani users get fake prize SMS messages, wallet "verification" requests, fake parcel alerts, and job offers that ask for a fee. These arrive in English, Urdu, and Roman Urdu. FraudLens PK lets a user paste a message and see:

- An advisory assessment: **Suspicious**, **Some Warning Signs**, or **Insufficient Evidence**
- The exact phrases that triggered each warning
- Why each warning sign matters, in English or Urdu
- Safer next steps

## Original Technical Contribution (Stage 1)

`detector.py` is a rule engine written from scratch:

- 7 explainable rules: OTP/PIN request, sensitive-info request, upfront payment, urgency/threat, prize claim, shortened URL, and well-known brand mention
- Patterns in English, Roman Urdu, and Urdu script
- Proximity matching: "OTP" is flagged only when a request verb ("share", "bata dein", "بھیجیں") is nearby, and negations like "do not share" are skipped
- Evidence spans are exact substrings of the message (this is enforced by a test)
- Severity-weighted scoring mapped to three labels, with no fake percentages
- Links are defanged for display (`bit.ly` → `bit[.]ly`) and never opened

## Installation (Windows)

```powershell
cd FraudLens-PK
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Run tests:

```powershell
python -m pytest -v
```

## Architecture (Stage 1)

```
User message ──► app.py (Streamlit UI)
                    │
                    ├──► detector.py  ── 7 regex rules ──► indicators + exact evidence ──► assessment
                    │
                    └──► ai_engine.py ── (Stage 2: not configured, shows setup notice)
```

## Test Findings (Stage 1, local detector only)

Run on 10 Oct 2026 with `python -m pytest -v`: **17 passed**. All messages are fictional.

| Test message | Expected | Actual | Rules triggered |
|---|---|---|---|
| Fake prize notification | Suspicious | Suspicious | upfront_payment, prize_claim, shortened_url |
| Fake wallet verification | Suspicious | Suspicious | otp_request, sensitive_info, urgency_threat, brand_mention |
| Fake delivery notification | Suspicious | Suspicious | upfront_payment, urgency_threat, shortened_url, brand_mention |
| Fake job registration fee | Suspicious | Suspicious | upfront_payment, prize_claim, brand_mention |
| Roman Urdu scam | Suspicious | Suspicious | otp_request, urgency_threat, prize_claim |
| University reminder | Insufficient Evidence | Insufficient Evidence | none |

Issue found and fixed during testing: the Roman Urdu phrases "qurandazi" and "jeet gaya" were not detected at first. The regexes were corrected and a regression test was added.

## Security

- `.env` is git-ignored. Only `.env.example` (no secrets) is committed.
- Messages are processed in memory only. They are never stored or logged.
- Links in messages are never opened. They are shown defanged and non-clickable.
- User text is shown only through `st.code` / the text box, never rendered as HTML or Markdown.
- Streamlit usage statistics are disabled in `.streamlit/config.toml`.

## Limitations

- Keyword rules can miss new scam wording and can flag legitimate messages.
- Roman Urdu spelling varies a lot, so coverage is partial.
- The detector cannot verify senders, links, or phone numbers.

## Team

| Member | Role |
|---|---|
| _Member 1 name_ | _e.g. detector rules and tests_ |
| _Member 2 name_ | _e.g. Streamlit UI and documentation_ |

## License and Acknowledgements

Original code is under the [MIT License](LICENSE).

Dependencies: [Streamlit](https://github.com/streamlit/streamlit) (Apache-2.0) and [pytest](https://github.com/pytest-dev/pytest) (MIT). Both licenses allow use in an MIT-licensed project.
