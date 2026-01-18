# TrackletGitHub.py
from __future__ import annotations

import os
import requests
from typing import Any


def _headers() -> dict[str, str]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Tracklet",
    }
    if token:
        # Works for public + private repos if token has access
        h["Authorization"] = f"Bearer {token}"
    return h


def get_releases(owner: str, repo: str, limit: int = 10) -> list[dict[str, Any]]:
    """
    Returns GitHub releases (published versions).
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    r = requests.get(url, headers=_headers(), timeout=12)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    data = (r.json() or [])[:limit]

    out = []
    for x in data:
        out.append(
            {
                "name": x.get("name") or x.get("tag_name") or "",
                "tag": x.get("tag_name") or "",
                "published_at": x.get("published_at"),
                "url": x.get("html_url"),
                "draft": bool(x.get("draft")),
                "prerelease": bool(x.get("prerelease")),
            }
        )
    return out


def get_tags(owner: str, repo: str, limit: int = 10) -> list[dict[str, Any]]:
    """
    Fallback if a repo uses tags but no releases.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    r = requests.get(url, headers=_headers(), timeout=12)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    data = (r.json() or [])[:limit]

    out = []
    for x in data:
        out.append(
            {
                "name": x.get("name") or "",
                "tag": x.get("name") or "",
                "published_at": None,
                "url": f"https://github.com/{owner}/{repo}/releases/tag/{x.get('name')}",
                "draft": False,
                "prerelease": False,
            }
        )
    return out
