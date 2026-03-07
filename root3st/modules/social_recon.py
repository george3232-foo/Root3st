"""Social media and person reconnaissance module.

Combines name-based searches, social-media profile scraping, and public
data aggregation for person-oriented OSINT.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

from root3st.config import Config
from root3st.utils import safe_request

# ---------------------------------------------------------------------------
# Name / person search via public search engines
# ---------------------------------------------------------------------------

def build_search_dorks(name: str) -> dict[str, str]:
    """Generate Google-style search dorks for a person's name."""
    encoded = quote_plus(name)
    return {
        "general": f"https://www.google.com/search?q=%22{encoded}%22",
        "linkedin": f"https://www.google.com/search?q=site%3Alinkedin.com+%22{encoded}%22",
        "facebook": f"https://www.google.com/search?q=site%3Afacebook.com+%22{encoded}%22",
        "twitter": f"https://www.google.com/search?q=site%3Atwitter.com+%22{encoded}%22",
        "instagram": f"https://www.google.com/search?q=site%3Ainstagram.com+%22{encoded}%22",
        "github": f"https://www.google.com/search?q=site%3Agithub.com+%22{encoded}%22",
        "reddit": f"https://www.google.com/search?q=site%3Areddit.com+%22{encoded}%22",
        "news": f"https://www.google.com/search?q=%22{encoded}%22&tbm=nws",
    }


# ---------------------------------------------------------------------------
# Social media profile fetchers (public data only)
# ---------------------------------------------------------------------------

def github_profile(username: str, config: Config) -> dict[str, Any]:
    """Fetch public GitHub profile data via the API (no auth needed)."""
    resp = safe_request(f"https://api.github.com/users/{username}", config=config)
    if resp and resp.ok:
        data = resp.json()
        return {
            "login": data.get("login"),
            "name": data.get("name"),
            "bio": data.get("bio"),
            "company": data.get("company"),
            "location": data.get("location"),
            "blog": data.get("blog"),
            "public_repos": data.get("public_repos"),
            "public_gists": data.get("public_gists"),
            "followers": data.get("followers"),
            "following": data.get("following"),
            "created_at": data.get("created_at"),
            "avatar_url": data.get("avatar_url"),
            "profile_url": data.get("html_url"),
        }
    return {}


def reddit_profile(username: str, config: Config) -> dict[str, Any]:
    """Fetch public Reddit profile data."""
    resp = safe_request(
        f"https://www.reddit.com/user/{username}/about.json",
        config=config,
    )
    if resp and resp.ok:
        try:
            data = resp.json().get("data", {})
            return {
                "name": data.get("name"),
                "link_karma": data.get("link_karma"),
                "comment_karma": data.get("comment_karma"),
                "created_utc": data.get("created_utc"),
                "is_gold": data.get("is_gold"),
                "verified": data.get("verified"),
                "has_verified_email": data.get("has_verified_email"),
                "icon_img": data.get("icon_img"),
            }
        except Exception:
            pass
    return {}


def gitlab_profile(username: str, config: Config) -> dict[str, Any]:
    """Fetch public GitLab profile data."""
    resp = safe_request(
        f"https://gitlab.com/api/v4/users?username={username}",
        config=config,
    )
    if resp and resp.ok:
        try:
            users = resp.json()
            if users:
                u = users[0]
                return {
                    "username": u.get("username"),
                    "name": u.get("name"),
                    "state": u.get("state"),
                    "avatar_url": u.get("avatar_url"),
                    "web_url": u.get("web_url"),
                }
        except Exception:
            pass
    return {}


# ---------------------------------------------------------------------------
# Orchestrator -- for "name" target type
# ---------------------------------------------------------------------------

def run_name(target: str, config: Config) -> dict[str, Any]:
    """Reconnaissance based on a person's full name."""
    return {
        "target": target,
        "type": "name",
        "search_dorks": build_search_dorks(target),
        "note": (
            "Open the dork URLs in a browser for results. Automated scraping of "
            "Google is blocked; the URLs are provided for manual investigation."
        ),
    }


# ---------------------------------------------------------------------------
# Orchestrator -- for "social" / userid target type
# ---------------------------------------------------------------------------

def run_social(target: str, config: Config) -> dict[str, Any]:
    """Reconnaissance on a social media username / userid.

    Fetches profiles from platforms with public APIs and checks existence
    on others.
    """
    results: dict[str, Any] = {"target": target, "type": "social"}

    # Platforms with structured APIs
    results["github"] = github_profile(target, config)
    results["reddit"] = reddit_profile(target, config)
    results["gitlab"] = gitlab_profile(target, config)

    # Search dorks for deeper investigation
    results["search_dorks"] = build_search_dorks(target)

    return results
