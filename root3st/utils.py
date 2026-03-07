"""Shared utility helpers for Root3st modules."""

from __future__ import annotations

import re
import socket
from typing import Any

import requests

from root3st.config import Config


def safe_request(
    url: str,
    *,
    config: Config | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    json_body: dict | None = None,
    timeout: int | None = None,
) -> requests.Response | None:
    """Perform an HTTP request, returning None on failure instead of raising."""
    cfg = config or Config()
    _headers = {"User-Agent": cfg.user_agent}
    if headers:
        _headers.update(headers)

    try:
        resp = requests.request(
            method,
            url,
            headers=_headers,
            params=params,
            json=json_body,
            timeout=timeout or cfg.timeout,
            allow_redirects=True,
        )
        return resp
    except requests.RequestException:
        return None


def resolve_hostname(hostname: str) -> str | None:
    """Resolve a hostname to its first IPv4 address, or None."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def is_valid_ip(value: str) -> bool:
    """Return True if value looks like a valid IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_valid_domain(value: str) -> bool:
    """Basic domain format validation."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_valid_email(value: str) -> bool:
    """Basic email format validation."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Flatten a nested dict into dot-separated keys."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
