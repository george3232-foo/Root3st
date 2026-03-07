"""Email address reconnaissance module.

Extracts domain information, validates MX records, checks for data breaches
(via HIBP), looks up Gravatar profiles, and performs additional enrichment.
"""

from __future__ import annotations

import hashlib
from typing import Any

import dns.resolver

from root3st.config import Config
from root3st.utils import safe_request

# ---------------------------------------------------------------------------
# Email parsing helpers
# ---------------------------------------------------------------------------

def parse_email(email: str) -> tuple[str, str]:
    """Split an email into (local_part, domain)."""
    local, _, domain = email.partition("@")
    return local, domain


# ---------------------------------------------------------------------------
# MX record validation
# ---------------------------------------------------------------------------

def check_mx_records(domain: str) -> list[str]:
    """Return MX records for the email domain, or empty list."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted(
            [rdata.exchange.to_text().rstrip(".") for rdata in answers],
            key=lambda x: x,
        )
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Have I Been Pwned (HIBP) breach check
# ---------------------------------------------------------------------------

def check_breaches_hibp(email: str, config: Config) -> list[dict[str, Any]]:
    """Check HIBP for breaches associated with the email.

    Requires a paid API key set via ``haveibeenpwned_api_key`` in config.
    Without a key, falls back to a simple informational stub.
    """
    if not config.haveibeenpwned_api_key:
        return [{"note": "HIBP check requires a paid API key (not configured)"}]

    resp = safe_request(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        config=config,
        headers={
            "hibp-api-key": config.haveibeenpwned_api_key,
            "User-Agent": "Root3st-OSINT",
        },
        params={"truncateResponse": "false"},
    )
    if resp and resp.ok:
        return resp.json()  # type: ignore[no-any-return]
    if resp and resp.status_code == 404:
        return []  # no breaches found
    return [{"error": f"HIBP returned status {resp.status_code}" if resp else "request failed"}]


# ---------------------------------------------------------------------------
# Gravatar profile
# ---------------------------------------------------------------------------

def gravatar_profile(email: str, config: Config) -> dict[str, Any]:
    """Look up the Gravatar profile associated with an email."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()  # noqa: S324
    resp = safe_request(
        f"https://gravatar.com/{email_hash}.json",
        config=config,
    )
    if resp and resp.ok:
        try:
            entry = resp.json().get("entry", [{}])[0]
            return {
                "display_name": entry.get("displayName"),
                "profile_url": entry.get("profileUrl"),
                "about": entry.get("aboutMe"),
                "location": entry.get("currentLocation"),
                "avatar_url": f"https://gravatar.com/avatar/{email_hash}",
                "accounts": [
                    {"shortname": a.get("shortname"), "url": a.get("url")}
                    for a in entry.get("accounts", [])
                ],
            }
        except Exception:
            pass
    return {}


# ---------------------------------------------------------------------------
# Hunter.io email verification
# ---------------------------------------------------------------------------

def hunter_verify(email: str, config: Config) -> dict[str, Any]:
    """Verify an email address via the Hunter.io API (if key configured)."""
    if not config.hunter_api_key:
        return {"note": "Hunter.io verification requires an API key (not configured)"}

    resp = safe_request(
        "https://api.hunter.io/v2/email-verifier",
        config=config,
        params={"email": email, "api_key": config.hunter_api_key},
    )
    if resp and resp.ok:
        data = resp.json().get("data", {})
        return {
            "status": data.get("status"),
            "score": data.get("score"),
            "disposable": data.get("disposable"),
            "webmail": data.get("webmail"),
            "mx_records": data.get("mx_records"),
            "smtp_server": data.get("smtp_server"),
        }
    return {}


# ---------------------------------------------------------------------------
# Email domain intelligence
# ---------------------------------------------------------------------------

def domain_email_intelligence(domain: str, config: Config) -> dict[str, Any]:
    """Gather basic intelligence about the email's domain."""
    info: dict[str, Any] = {}

    # SPF record
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                info["spf"] = txt
    except Exception:
        pass

    # DMARC record
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt:
                info["dmarc"] = txt
    except Exception:
        pass

    return info


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(target: str, config: Config) -> dict[str, Any]:
    """Execute full email reconnaissance and return aggregated results."""
    local_part, domain = parse_email(target)
    results: dict[str, Any] = {
        "target": target,
        "type": "email",
        "local_part": local_part,
        "domain": domain,
    }

    # MX records
    results["mx_records"] = check_mx_records(domain)

    # Domain email intelligence (SPF, DMARC)
    results["domain_email_security"] = domain_email_intelligence(domain, config)

    # Gravatar
    results["gravatar"] = gravatar_profile(target, config)

    # HIBP breach check
    results["breaches"] = check_breaches_hibp(target, config)

    # Hunter.io verification
    results["hunter_verification"] = hunter_verify(target, config)

    return results
