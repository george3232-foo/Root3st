"""Phone number reconnaissance module.

Performs carrier lookup, number validation, and format analysis for phone
numbers.  Uses freely available heuristics and public APIs.
"""

from __future__ import annotations

import re
from typing import Any

from root3st.config import Config
from root3st.utils import safe_request

# ---------------------------------------------------------------------------
# Number normalisation
# ---------------------------------------------------------------------------

def normalise_number(phone: str) -> str:
    """Strip non-numeric characters except leading +."""
    cleaned = re.sub(r"[^\d+]", "", phone)
    return cleaned


# ---------------------------------------------------------------------------
# Number format analysis
# ---------------------------------------------------------------------------

# Simplified country code mapping (top prefixes)
COUNTRY_CODES: dict[str, str] = {
    "1": "US/CA",
    "7": "RU/KZ",
    "20": "EG",
    "27": "ZA",
    "30": "GR",
    "31": "NL",
    "32": "BE",
    "33": "FR",
    "34": "ES",
    "36": "HU",
    "39": "IT",
    "40": "RO",
    "41": "CH",
    "43": "AT",
    "44": "GB",
    "45": "DK",
    "46": "SE",
    "47": "NO",
    "48": "PL",
    "49": "DE",
    "51": "PE",
    "52": "MX",
    "53": "CU",
    "54": "AR",
    "55": "BR",
    "56": "CL",
    "57": "CO",
    "58": "VE",
    "60": "MY",
    "61": "AU",
    "62": "ID",
    "63": "PH",
    "64": "NZ",
    "65": "SG",
    "66": "TH",
    "81": "JP",
    "82": "KR",
    "84": "VN",
    "86": "CN",
    "90": "TR",
    "91": "IN",
    "92": "PK",
    "93": "AF",
    "94": "LK",
    "95": "MM",
    "98": "IR",
    "212": "MA",
    "213": "DZ",
    "216": "TN",
    "218": "LY",
    "220": "GM",
    "234": "NG",
    "254": "KE",
    "255": "TZ",
    "256": "UG",
    "260": "ZM",
    "263": "ZW",
    "351": "PT",
    "352": "LU",
    "353": "IE",
    "354": "IS",
    "358": "FI",
    "370": "LT",
    "371": "LV",
    "372": "EE",
    "380": "UA",
    "420": "CZ",
    "421": "SK",
    "852": "HK",
    "853": "MO",
    "855": "KH",
    "856": "LA",
    "880": "BD",
    "886": "TW",
    "960": "MV",
    "961": "LB",
    "962": "JO",
    "963": "SY",
    "964": "IQ",
    "965": "KW",
    "966": "SA",
    "967": "YE",
    "968": "OM",
    "971": "AE",
    "972": "IL",
    "973": "BH",
    "974": "QA",
    "975": "BT",
    "976": "MN",
    "977": "NP",
    "992": "TJ",
    "993": "TM",
    "994": "AZ",
    "995": "GE",
    "996": "KG",
    "998": "UZ",
}


def identify_country(number: str) -> dict[str, str]:
    """Attempt to identify the country from the phone number prefix."""
    digits = number.lstrip("+")
    # Try 3-digit, then 2-digit, then 1-digit prefix
    for length in (3, 2, 1):
        prefix = digits[:length]
        if prefix in COUNTRY_CODES:
            return {"country_code": f"+{prefix}", "country": COUNTRY_CODES[prefix]}
    return {"country_code": "unknown", "country": "unknown"}


def analyse_format(phone: str) -> dict[str, Any]:
    """Analyse the phone number format and extract metadata."""
    number = normalise_number(phone)
    is_international = number.startswith("+")

    info: dict[str, Any] = {
        "original": phone,
        "normalised": number,
        "is_international": is_international,
        "digit_count": len(number.lstrip("+")),
    }

    if is_international:
        info.update(identify_country(number))

    return info


# ---------------------------------------------------------------------------
# NumVerify API (free tier, optional)
# ---------------------------------------------------------------------------

def numverify_lookup(phone: str, config: Config) -> dict[str, Any]:
    """Use the NumVerify API for carrier/line-type data (free tier available)."""
    # NumVerify free key can be set via env NUMVERIFY_API_KEY
    import os

    api_key = os.getenv("NUMVERIFY_API_KEY", "")
    if not api_key:
        return {"note": "NumVerify lookup requires NUMVERIFY_API_KEY env var (not configured)"}

    number = normalise_number(phone).lstrip("+")
    resp = safe_request(
        "http://apilayer.net/api/validate",
        config=config,
        params={"access_key": api_key, "number": number},
    )
    if resp and resp.ok:
        data = resp.json()
        return {
            "valid": data.get("valid"),
            "country_name": data.get("country_name"),
            "location": data.get("location"),
            "carrier": data.get("carrier"),
            "line_type": data.get("line_type"),
        }
    return {}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(target: str, config: Config) -> dict[str, Any]:
    """Execute phone number reconnaissance and return aggregated results."""
    results: dict[str, Any] = {"target": target, "type": "phone"}

    # Format analysis
    results["format_analysis"] = analyse_format(target)

    # NumVerify lookup
    results["numverify"] = numverify_lookup(target, config)

    return results
