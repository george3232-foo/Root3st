"""Domain reconnaissance module.

Performs DNS enumeration, WHOIS, SSL certificate inspection, subdomain
discovery (via crt.sh), HTTP header analysis, and technology detection.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any

import dns.resolver
import whois as python_whois

from root3st.config import Config
from root3st.utils import resolve_hostname, safe_request

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]


def enumerate_dns(domain: str) -> dict[str, list[str]]:
    """Query common DNS record types for a domain."""
    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout, Exception):
            continue

    return records


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def whois_domain(domain: str) -> dict[str, Any]:
    """Retrieve WHOIS data for a domain."""
    try:
        w = python_whois.whois(domain)
        data = {k: v for k, v in w.items() if v is not None}
        # Serialise datetime objects
        for key, val in data.items():
            if isinstance(val, datetime):
                data[key] = val.isoformat()
            elif isinstance(val, list):
                data[key] = [
                    v.isoformat() if isinstance(v, datetime) else v for v in val
                ]
        return data
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# SSL certificate
# ---------------------------------------------------------------------------

def ssl_certificate_info(domain: str) -> dict[str, Any]:
    """Fetch TLS certificate details from the target domain."""
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        if not cert:
            return {}

        return {
            "subject": dict(x[0] for x in cert.get("subject", ())),
            "issuer": dict(x[0] for x in cert.get("issuer", ())),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [
                entry[1]
                for entry in cert.get("subjectAltName", ())
            ],
            "version": cert.get("version"),
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Subdomain discovery via Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

def discover_subdomains_crtsh(domain: str, config: Config) -> list[str]:
    """Query crt.sh for subdomains observed in certificate transparency logs."""
    resp = safe_request(
        f"https://crt.sh/?q=%.{domain}&output=json",
        config=config,
        timeout=20,
    )
    if not resp or not resp.ok:
        return []

    try:
        entries = resp.json()
    except Exception:
        return []

    subdomains: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)

    return sorted(subdomains)


# ---------------------------------------------------------------------------
# HTTP headers & technology fingerprinting
# ---------------------------------------------------------------------------

TECH_HEADERS = {
    "X-Powered-By": "server_tech",
    "Server": "server_software",
    "X-AspNet-Version": "aspnet_version",
    "X-Generator": "generator",
    "X-Drupal-Cache": "drupal",
    "X-Varnish": "varnish",
    "Via": "proxy_via",
    "X-Cache": "cache_status",
    "X-CDN": "cdn",
    "CF-Ray": "cloudflare",
}


def analyse_http_headers(domain: str, config: Config) -> dict[str, Any]:
    """Fetch HTTP headers and extract technology fingerprints."""
    result: dict[str, Any] = {"headers": {}, "technologies": {}}

    for scheme in ("https", "http"):
        resp = safe_request(f"{scheme}://{domain}", config=config)
        if resp is None:
            continue

        headers = dict(resp.headers)
        result["headers"] = headers
        result["final_url"] = resp.url
        result["status_code"] = resp.status_code

        techs: dict[str, str] = {}
        for header_name, label in TECH_HEADERS.items():
            val = headers.get(header_name)
            if val:
                techs[label] = val

        # Check for common meta-generators in body
        body = resp.text[:8000].lower()
        if "wordpress" in body:
            techs["cms"] = "WordPress"
        elif "joomla" in body:
            techs["cms"] = "Joomla"
        elif "drupal" in body:
            techs["cms"] = "Drupal"
        if "cloudflare" in headers.get("Server", "").lower():
            techs["cdn"] = "Cloudflare"

        result["technologies"] = techs
        break  # success on first scheme

    return result


# ---------------------------------------------------------------------------
# robots.txt & security.txt
# ---------------------------------------------------------------------------

def fetch_special_files(domain: str, config: Config) -> dict[str, str | None]:
    """Fetch robots.txt and .well-known/security.txt if present."""
    files: dict[str, str | None] = {}
    for path in ("robots.txt", ".well-known/security.txt"):
        resp = safe_request(f"https://{domain}/{path}", config=config)
        if resp and resp.ok:
            files[path] = resp.text[:4000]
        else:
            files[path] = None
    return files


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(target: str, config: Config) -> dict[str, Any]:
    """Execute full domain reconnaissance and return aggregated results."""
    results: dict[str, Any] = {"target": target, "type": "domain"}

    # Resolve IP
    ip = resolve_hostname(target)
    results["resolved_ip"] = ip

    # DNS records
    results["dns_records"] = enumerate_dns(target)

    # WHOIS
    results["whois"] = whois_domain(target)

    # SSL certificate
    results["ssl_certificate"] = ssl_certificate_info(target)

    # Subdomains via crt.sh
    results["subdomains"] = discover_subdomains_crtsh(target, config)

    # HTTP header analysis
    results["http_analysis"] = analyse_http_headers(target, config)

    # Special files
    results["special_files"] = fetch_special_files(target, config)

    return results
