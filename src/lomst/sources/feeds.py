"""Generic RSS and WordPress connectors.

One WordPress connector serves three of the requested sources (OWASP GenAI,
Obot, Artiverse) because all three expose the standard `wp-json` REST API, which
carries modification dates, categories and tags that the plain `/feed/` does not.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..config import SourceConfig
from ..http import fetch
from .base import Observation, Result, iso_date, strip_html

_NS = {
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "atom": "http://www.w3.org/2005/Atom",
}


class RssConnector:
    """RSS 2.0 / Atom feed reader (RadarAI, and any feed-only source)."""

    name = "rss"

    def fetch(self, cfg: SourceConfig) -> Result:
        if not cfg.url:
            raise ValueError(f"source {cfg.id} requires a url")
        resp = fetch(cfg.url)
        return Result(observations=list(self._parse(resp.text, cfg)))

    def _parse(self, xml: str, cfg: SourceConfig):
        root = ET.fromstring(xml.encode("utf-8", "replace"))
        # RSS puts items under channel/item; Atom uses top-level entry.
        items = root.findall(".//item") or root.findall(".//atom:entry", _NS)
        for item in items:
            title = self._text(item, "title")
            link = self._text(item, "link") or self._atom_link(item)
            guid = self._text(item, "guid") or self._text(item, "atom:id") or link or title
            if not guid:
                continue
            body = (
                self._text(item, "content:encoded")
                or self._text(item, "description")
                or self._text(item, "atom:summary")
            )
            published = (
                self._text(item, "pubDate")
                or self._text(item, "atom:updated")
                or self._text(item, "dc:date")
            )
            categories = [c.text for c in item.findall("category") if c.text]
            yield Observation(
                external_id=guid.strip(),
                kind="feed_item",
                title=strip_html(title, 300),
                url=link,
                summary=strip_html(body),
                published_at=iso_date(published),
                payload={"categories": categories, "source_name": cfg.name},
            )

    @staticmethod
    def _text(node: ET.Element, tag: str) -> str | None:
        el = node.find(tag, _NS) if ":" in tag else node.find(tag)
        return el.text if el is not None and el.text else None

    @staticmethod
    def _atom_link(node: ET.Element) -> str | None:
        for link in node.findall("atom:link", _NS):
            if link.get("rel") in (None, "alternate"):
                return link.get("href")
        return None


class WordPressConnector:
    """WordPress REST API reader.

    Falls back to `/feed/` when `wp-json` is unavailable or blocked, so a site
    that later disables the REST API degrades instead of going dark.
    """

    name = "wordpress"

    def fetch(self, cfg: SourceConfig) -> Result:
        if not cfg.url:
            raise ValueError(f"source {cfg.id} requires a url")
        base = cfg.url.rstrip("/")
        per_page = int(cfg.options.get("per_page", 40))
        pages = int(cfg.options.get("pages", 1))

        observations: list[Observation] = []
        try:
            for page in range(1, pages + 1):
                resp = fetch(
                    f"{base}/wp-json/wp/v2/posts",
                    params={
                        "per_page": per_page,
                        "page": page,
                        "orderby": "modified",
                        "order": "desc",
                        "_fields": "id,link,date_gmt,modified_gmt,title,excerpt,categories,tags",
                    },
                )
                batch: list[dict[str, Any]] = resp.json()
                if not batch:
                    break
                observations.extend(self._from_wp(batch, cfg))
                if len(batch) < per_page:
                    break
        except Exception:
            # REST unavailable: fall back to the syndication feed.
            fallback = RssConnector().fetch(
                SourceConfig(
                    id=cfg.id, name=cfg.name, connector="rss", tier=cfg.tier,
                    url=f"{base}/feed/",
                )
            )
            fallback.attribution = f"{cfg.name} (via /feed/ fallback)"
            return fallback

        return Result(observations=observations)

    def _from_wp(self, batch: list[dict[str, Any]], cfg: SourceConfig):
        for post in batch:
            title = (post.get("title") or {}).get("rendered")
            excerpt = (post.get("excerpt") or {}).get("rendered")
            yield Observation(
                external_id=f"wp:{post['id']}",
                kind="article",
                title=strip_html(title, 300),
                url=post.get("link"),
                summary=strip_html(excerpt),
                published_at=iso_date(post.get("date_gmt")),
                payload={
                    "modified_gmt": iso_date(post.get("modified_gmt")),
                    "categories": post.get("categories") or [],
                    "tags": post.get("tags") or [],
                    "source_name": cfg.name,
                },
            )
