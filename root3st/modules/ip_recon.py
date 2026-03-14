"""IP address reconnaissance module.

Performs WHOIS, geolocation, reverse DNS, port scanning, and abuse/reputation
lookups against a target IPv4 address.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from root3st.config import Config
from root3st.utils import reverse_dns, safe_request


def geolocate_ip(ip: str, config: Config) -> dict[str, Any]:
    """Query ip-api.com for geolocation data (free, no key required)."""
    resp = safe_request(f"https://ip-api.com/json/{ip}?fields=66846719", config=config)
    if resp and resp.ok:
        return resp.json()
    return {}


def whois_ip(ip: str) -> dict[str, Any]:
    """Retrieve WHOIS information for an IP via RDAP (ARIN)."""
    import whois as python_whois  # python-whois

    try:
        w = python_whois.whois(ip)
        return {k: v for k, v in w.items() if v is not None}
    except Exception:
        return {}


def abuse_ipdb_check(ip: str, config: Config) -> dict[str, Any]:
    """Check AbuseIPDB if an API key is configured (optional enrichment)."""
    # This is a stub -- requires AbuseIPDB key which is optional.
    return {"note": "AbuseIPDB check requires an API key (not configured)"}


def shodan_lookup(ip: str, config: Config) -> dict[str, Any]:
    """Query Shodan for host information if an API key is available."""
    if not config.shodan_api_key:
        return {"note": "Shodan lookup requires an API key (not configured)"}

    resp = safe_request(
        f"https://api.shodan.io/shodan/host/{ip}",
        config=config,
        params={"key": config.shodan_api_key},
    )
    if resp and resp.ok:
        data = resp.json()
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "os": data.get("os"),
            "vulns": data.get("vulns", []),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "last_update": data.get("last_update"),
        }
    return {}


def virustotal_ip(ip: str, config: Config) -> dict[str, Any]:
    """Query VirusTotal for IP reputation if an API key is available."""
    if not config.virustotal_api_key:
        return {"note": "VirusTotal lookup requires an API key (not configured)"}

    resp = safe_request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        config=config,
        headers={"x-apikey": config.virustotal_api_key},
    )
    if resp and resp.ok:
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "reputation": attrs.get("reputation"),
            "analysis_stats": stats,
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "network": attrs.get("network"),
        }
    return {}


async def _scan_port(ip: str, port: int, timeout: float) -> int | None:
    """Attempt to connect to a single port; return port number if open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, OSError):
        return None


async def scan_ports_async(ip: str, config: Config) -> list[dict[str, Any]]:
    """Scan common ports concurrently and return open ports with service guesses."""
    sem = asyncio.Semaphore(config.max_concurrent)

    async def _guarded(port: int) -> int | None:
        async with sem:
            return await _scan_port(ip, port, config.port_scan_timeout)

    tasks = [_guarded(p) for p in config.ports]
    results = await asyncio.gather(*tasks)

    open_ports: list[dict[str, Any]] = []
    for port in results:
        if port is not None:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            open_ports.append({"port": port, "service": service, "state": "open"})

    return sorted(open_ports, key=lambda p: p["port"])


def scan_ports(ip: str, config: Config) -> list[dict[str, Any]]:
    """Synchronous wrapper around the async port scanner."""
    return asyncio.run(scan_ports_async(ip, config))


def run(target: str, config: Config) -> dict[str, Any]:
    """Execute full IP reconnaissance and return aggregated results."""
    results: dict[str, Any] = {"target": target, "type": "ip"}

    # Reverse DNS
    rdns = reverse_dns(target)
    results["reverse_dns"] = rdns

    # Geolocation
    results["geolocation"] = geolocate_ip(target, config)

    # WHOIS
    results["whois"] = whois_ip(target)

    # Port scan
    results["open_ports"] = scan_ports(target, config)

    # Shodan enrichment
    results["shodan"] = shodan_lookup(target, config)

    # VirusTotal enrichment
    results["virustotal"] = virustotal_ip(target, config)

    return results
