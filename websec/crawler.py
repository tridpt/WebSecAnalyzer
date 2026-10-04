"""Small, same-origin crawler for owner-authorized website checks."""

from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import parse_qsl, urljoin, urlsplit
from xml.etree import ElementTree

import requests

from .fetch import (
    OutOfScope, RequestLimitReached, RequestPacer, fetch, origin,
    without_fragment,
)
from .targets import InvalidTarget, is_loopback_host
from .network import DNSChanged
from .control import ScanControl

MAX_PAGES = 30
MAX_SITEMAPS = 3
_STATE_CHANGING_SEGMENTS = {
    "delete", "remove", "logout", "signout", "unsubscribe", "destroy",
}
_SKIP_EXTENSIONS = (
    ".7z", ".avi", ".css", ".csv", ".gif", ".ico", ".jpeg", ".jpg",
    ".js", ".json", ".mp3", ".mp4", ".pdf", ".png", ".svg", ".webp",
    ".woff", ".woff2", ".xml", ".zip",
)


def is_html(response: requests.Response) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    return not content_type or "html" in content_type


def _eligible(url: str, site_origin: tuple[str, str, int]) -> bool:
    try:
        parsed = urlsplit(url)
        query_parts = parse_qsl(parsed.query, keep_blank_values=True)
        changes_state = any(
            key.lower() in _STATE_CHANGING_SEGMENTS
            or (key.lower() in {"action", "do"} and value.lower() in _STATE_CHANGING_SEGMENTS)
            for key, value in query_parts
        )
        return (
            parsed.scheme in {"http", "https"}
            and origin(url) == site_origin
            and not parsed.path.lower().endswith(_SKIP_EXTENSIONS)
            and not set(parsed.path.lower().split("/")) & _STATE_CHANGING_SEGMENTS
            and not changes_state
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.hrefs.append(value)


def extract_links(html: str, base_url: str, site_origin: tuple[str, str, int]) -> list[str]:
    parser = _Links()
    parser.feed(html)
    return filter_links(parser.hrefs, base_url, site_origin)


def filter_links(
    hrefs: list[str], base_url: str, site_origin: tuple[str, str, int],
) -> list[str]:
    """Apply the same scope and safety rules to HTML and rendered anchors."""
    found: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        try:
            candidate = without_fragment(urljoin(base_url, href.strip()))
        except ValueError:
            continue
        if candidate not in seen and _eligible(candidate, site_origin):
            seen.add(candidate)
            found.append(candidate)
    return found


def sitemap_urls(
    session: requests.Session,
    site_url: str,
    *,
    timeout: float,
    allow_private: bool,
    pacer: RequestPacer,
    max_urls: int,
    control: ScanControl | None = None,
) -> list[str]:
    """Read a sitemap or small sitemap index without leaving the site origin."""
    parsed = urlsplit(site_url)
    site_origin = origin(site_url)
    queue = deque([f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"])
    seen_sitemaps: set[str] = set()
    pages: list[str] = []
    seen_pages: set[str] = set()

    while queue and len(seen_sitemaps) < MAX_SITEMAPS and len(pages) < max_urls:
        if control:
            control.check()
        sitemap_url = queue.popleft()
        if sitemap_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap_url)
        try:
            response = fetch(
                session, sitemap_url, timeout=timeout, allow_private=allow_private,
                pacer=pacer, expected_origin=site_origin,
                initial_loopback=is_loopback_host(parsed.hostname),
                control=control,
            )
        except DNSChanged:
            raise
        except RequestLimitReached:
            break
        except (InvalidTarget, requests.RequestException):
            continue
        if response.status_code >= 400:
            continue
        try:
            root = ElementTree.fromstring(response.content)
        except ElementTree.ParseError:
            continue

        root_name = root.tag.rsplit("}", 1)[-1].lower()
        locs = [
            element.text.strip()
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text
        ]
        for loc in locs:
            candidate = without_fragment(loc)
            if root_name == "sitemapindex":
                try:
                    if origin(candidate) == site_origin and candidate.lower().endswith(".xml"):
                        queue.append(candidate)
                except ValueError:
                    continue
            elif _eligible(candidate, site_origin) and candidate not in seen_pages:
                seen_pages.add(candidate)
                pages.append(candidate)
                if len(pages) >= max_urls:
                    break
    return pages


def crawl_pages(
    session: requests.Session,
    start_url: str,
    start_response: requests.Response,
    *,
    max_pages: int,
    timeout: float,
    allow_private: bool,
    pacer: RequestPacer,
    control: ScanControl | None = None,
    discover_links: Callable[[requests.Response], list[str]] | None = None,
) -> tuple[list[tuple[str, requests.Response]], int, int]:
    """Return HTML pages and number of discovered URLs skipped or not scanned."""
    site_origin = origin(start_response.url)
    start_loopback = is_loopback_host(urlsplit(start_response.url).hostname)
    if not is_html(start_response):
        return [], 1, 0
    pages = [(start_url, start_response)]
    if max_pages == 1 and discover_links is None:
        return pages, 0, 0
    queue: deque[str] = deque()
    seen = {without_fragment(start_response.url), without_fragment(start_url)}
    max_candidates = max_pages * 4

    def enqueue(urls: list[str]) -> int:
        added = 0
        for candidate in urls:
            if len(seen) >= max_candidates or candidate in seen:
                continue
            seen.add(candidate)
            queue.append(candidate)
            added += 1
        return added

    js_discovered = 0

    def enqueue_rendered(response: requests.Response) -> None:
        nonlocal js_discovered
        if discover_links is not None:
            js_discovered += enqueue(filter_links(
                discover_links(response), response.url, site_origin,
            ))

    enqueue(extract_links(start_response.text, start_response.url, site_origin))
    enqueue_rendered(start_response)
    if max_pages > 1:
        enqueue(sitemap_urls(
            session, start_response.url, timeout=timeout, allow_private=allow_private,
            pacer=pacer, max_urls=max_candidates,
            control=control,
        ))

    attempts = 0
    skipped = 0
    while queue and len(pages) < max_pages and attempts < max_pages * 3:
        if control:
            control.check()
        candidate = queue.popleft()
        attempts += 1
        try:
            response = fetch(
                session, candidate, timeout=timeout, allow_private=allow_private,
                pacer=pacer, expected_origin=site_origin,
                initial_loopback=start_loopback,
                control=control,
            )
        except DNSChanged:
            raise
        except RequestLimitReached:
            skipped += 1
            break
        except (OutOfScope, InvalidTarget, requests.RequestException):
            skipped += 1
            continue
        if response.status_code >= 400 or not is_html(response):
            skipped += 1
            continue
        final_url = without_fragment(response.url)
        if any(without_fragment(page_response.url) == final_url for _, page_response in pages):
            continue
        pages.append((candidate, response))
        enqueue(extract_links(response.text, response.url, site_origin))
        enqueue_rendered(response)

    return pages, skipped + len(queue), js_discovered
