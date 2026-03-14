"""Username reconnaissance module.

Checks for the existence of a username across dozens of popular platforms
by making HTTP requests and interpreting status codes and page content.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from root3st.config import USERNAME_PLATFORMS, Config


async def _check_platform(
    session: aiohttp.ClientSession,
    platform: str,
    url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> dict[str, Any]:
    """Check if a username exists on a single platform."""
    async with semaphore:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=True) as resp:
                status = resp.status
                final_url = str(resp.url)
                # Check if we were redirected to a login/signup page
                login_indicators = ("/login", "/signin", "/signup", "/join", "/account",
                                    "/auth", "/register", "/sign-up", "/log-in")
                if final_url != url and any(ind in final_url.lower() for ind in login_indicators):
                    return {"platform": platform, "url": url, "status": "not_found"}
                # Most platforms return 404 when the user doesn't exist
                if status == 200:
                    return {"platform": platform, "url": url, "status": "found"}
                elif status == 404:
                    return {"platform": platform, "url": url, "status": "not_found"}
                else:
                    return {"platform": platform, "url": url, "status": "uncertain",
                            "http_status": status}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return {"platform": platform, "url": url, "status": "error"}


async def check_platforms_async(
    username: str,
    config: Config,
    platforms: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Check username existence across platforms concurrently."""
    _platforms = platforms or USERNAME_PLATFORMS
    sem = asyncio.Semaphore(config.max_concurrent)

    headers = {"User-Agent": config.user_agent}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [
            _check_platform(
                session, name, url.format(username=username), sem, config.timeout
            )
            for name, url in _platforms.items()
        ]
        results = await asyncio.gather(*tasks)

    return sorted(results, key=lambda r: r["platform"])


def check_platforms(
    username: str,
    config: Config,
    platforms: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Synchronous wrapper around the async platform checker."""
    return asyncio.run(check_platforms_async(username, config, platforms))


def run(target: str, config: Config) -> dict[str, Any]:
    """Execute full username reconnaissance and return aggregated results."""
    all_results = check_platforms(target, config)

    found = [r for r in all_results if r["status"] == "found"]
    not_found = [r for r in all_results if r["status"] == "not_found"]
    uncertain = [r for r in all_results if r["status"] in ("uncertain", "error")]

    return {
        "target": target,
        "type": "username",
        "total_checked": len(all_results),
        "found_count": len(found),
        "found": found,
        "not_found": not_found,
        "uncertain": uncertain,
    }
