"""Configuration management for Root3st."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path.home() / ".root3st" / "config.yaml"

# Default timeout for HTTP requests (seconds)
DEFAULT_TIMEOUT = 15

# Default user agent string
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Username check platforms with URL templates.
# {username} is replaced with the target username.
USERNAME_PLATFORMS: dict[str, str] = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Twitter/X": "https://x.com/{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "Reddit": "https://www.reddit.com/user/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Medium": "https://medium.com/@{username}",
    "Dev.to": "https://dev.to/{username}",
    "Keybase": "https://keybase.io/{username}",
    "HackerNews": "https://news.ycombinator.com/user?id={username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}",
    "StackOverflow": "https://stackoverflow.com/users/?tab=accounts&SearchOn=DisplayName&Search={username}",
    "DockerHub": "https://hub.docker.com/u/{username}",
    "PyPI": "https://pypi.org/user/{username}/",
    "npm": "https://www.npmjs.com/~{username}",
    "Replit": "https://replit.com/@{username}",
    "Flickr": "https://www.flickr.com/people/{username}/",
    "Vimeo": "https://vimeo.com/{username}",
    "SoundCloud": "https://soundcloud.com/{username}",
    "Spotify": "https://open.spotify.com/user/{username}",
    "Patreon": "https://www.patreon.com/{username}",
    "Gravatar": "https://gravatar.com/{username}",
    "About.me": "https://about.me/{username}",
    "500px": "https://500px.com/p/{username}",
    "Dribbble": "https://dribbble.com/{username}",
    "Behance": "https://www.behance.net/{username}",
}

# Common ports to scan
COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090,
]


@dataclass
class Config:
    """Application configuration loaded from YAML or environment."""

    # API keys (optional, enhances results)
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    hunter_api_key: str = ""
    haveibeenpwned_api_key: str = ""

    # Behaviour settings
    timeout: int = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    max_concurrent: int = 20
    port_scan_timeout: float = 1.5
    ports: list[int] = field(default_factory=lambda: list(COMMON_PORTS))

    # Output settings
    output_dir: str = "./reports"

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        """Load config from YAML file, falling back to env vars and defaults."""
        data: dict = {}
        config_path = path or DEFAULT_CONFIG_PATH

        if config_path.exists():
            with open(config_path) as fh:
                data = yaml.safe_load(fh) or {}

        # Environment variables override file settings
        return cls(
            shodan_api_key=os.getenv("SHODAN_API_KEY", data.get("shodan_api_key", "")),
            virustotal_api_key=os.getenv(
                "VIRUSTOTAL_API_KEY", data.get("virustotal_api_key", "")
            ),
            hunter_api_key=os.getenv("HUNTER_API_KEY", data.get("hunter_api_key", "")),
            haveibeenpwned_api_key=os.getenv(
                "HAVEIBEENPWNED_API_KEY", data.get("haveibeenpwned_api_key", "")
            ),
            timeout=int(data.get("timeout", DEFAULT_TIMEOUT)),
            user_agent=data.get("user_agent", DEFAULT_USER_AGENT),
            max_concurrent=int(data.get("max_concurrent", 20)),
            port_scan_timeout=float(data.get("port_scan_timeout", 1.5)),
            ports=data.get("ports", list(COMMON_PORTS)),
            output_dir=data.get("output_dir", "./reports"),
        )
