"""Shared HTTP access with retries, backoff and robots.txt enforcement."""

from __future__ import annotations

import hashlib
import logging
import os
import time
import urllib.robotparser as robotparser
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

USER_AGENT = os.environ.get(
    "LOMST_USER_AGENT",
    "lomst/0.1 (Paradox Interactive AI governance model tracker; +internal)",
)

RETRY_STATUS = {429, 500, 502, 503, 504}


class FetchError(RuntimeError):
    """A source could not be fetched after retries."""


class RobotsDenied(FetchError):
    """robots.txt forbids this path for our user agent."""


@lru_cache(maxsize=64)
def _robots_for(origin: str) -> robotparser.RobotFileParser | None:
    rp = robotparser.RobotFileParser()
    rp.set_url(f"{origin}/robots.txt")
    try:
        resp = httpx.get(
            f"{origin}/robots.txt",
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            # No usable robots.txt: nothing is disallowed.
            return None
        rp.parse(resp.text.splitlines())
        return rp
    except httpx.HTTPError:
        # Fail open on robots retrieval, but never on an explicit Disallow.
        return None


def robots_allows(url: str) -> bool:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    rp = _robots_for(origin)
    if rp is None:
        return True
    return rp.can_fetch(USER_AGENT, url)


def fetch(
    url: str,
    *,
    method: str = "GET",
    json_body: Any = None,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    attempts: int = 3,
    timeout: float = 30.0,
    check_robots: bool = True,
) -> httpx.Response:
    """Fetch a URL, honouring robots.txt and retrying transient failures.

    robots.txt is checked for every request by default. llm-stats.com disallows
    /api/, and the tracker must respect that rather than route around it.
    """
    if check_robots and not robots_allows(url):
        raise RobotsDenied(f"robots.txt disallows {url} for {USER_AGENT!r}")

    hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"}
    hdrs.update(headers or {})

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            resp = httpx.request(
                method,
                url,
                json=json_body,
                headers=hdrs,
                params=params,
                timeout=timeout,
                follow_redirects=True,
            )
            if resp.status_code in RETRY_STATUS:
                raise httpx.HTTPStatusError(
                    f"retryable status {resp.status_code}", request=resp.request, response=resp
                )
            resp.raise_for_status()
            return resp
        except httpx.HTTPError as exc:
            last = exc
            if attempt == attempts:
                break
            sleep = min(2**attempt, 10)
            log.warning("fetch %s failed (attempt %d/%d): %s", url, attempt, attempts, exc)
            time.sleep(sleep)

    raise FetchError(f"{url}: {last}") from last


def github_headers() -> dict[str, str]:
    """GitHub API headers, authenticated when a token is present.

    Unauthenticated GitHub allows 60 requests/hour, which is enough for a daily
    run but breaks under repeated testing. GITHUB_TOKEN raises it to 5000/hour.
    """
    hdrs = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    return hdrs


def content_hash(*parts: Any) -> str:
    """Stable hash used to distinguish a changed item from a re-seen one."""
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p if p is not None else "").encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()[:32]
