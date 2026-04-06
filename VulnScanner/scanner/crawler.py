"""
Web Crawler / Spider
Discovers URLs, forms, and parameters on the target.
"""

import re
import time
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field
from bs4 import BeautifulSoup


@dataclass
class FormData:
    url: str
    action: str
    method: str
    inputs: list = field(default_factory=list)


class Crawler:
    def __init__(
        self,
        target: str,
        max_depth: int = 3,
        max_pages: int = 100,
        timeout: int = 10,
        rate_limit: float = 0.1,
        user_agent: str = "VulnScanner/1.0",
        verify_ssl: bool = False,
    ):
        self.target = target
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl

        parsed = urlparse(target)
        self.base_domain = parsed.netloc
        self.scheme = parsed.scheme

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = verify_ssl

        self.visited = set()
        self.urls_with_params = []
        self.forms = []

    def crawl(self) -> tuple:
        self._crawl_recursive(self.target, depth=0)
        all_urls = list(self.visited)
        return all_urls, self.forms

    def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return

        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return

        if not self._is_in_scope(url):
            return

        self.visited.add(normalized)

        try:
            time.sleep(self.rate_limit)
            response = self.session.get(
                url, timeout=self.timeout, allow_redirects=True
            )
        except requests.RequestException:
            return

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return

        # Track URLs with query parameters
        parsed = urlparse(url)
        if parsed.query:
            self.urls_with_params.append(url)

        soup = BeautifulSoup(response.text, "html.parser")

        # Extract forms
        self._extract_forms(url, soup)

        # Extract links
        links = self._extract_links(url, soup)
        for link in links:
            self._crawl_recursive(link, depth + 1)

    def _extract_links(self, base_url: str, soup: BeautifulSoup) -> list:
        links = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(base_url, href)
            # Remove fragments
            full_url = full_url.split("#")[0]
            if full_url and self._is_in_scope(full_url):
                links.append(full_url)

        # Also extract from script src, form actions, etc.
        for tag in soup.find_all(["script", "link", "iframe"], src=True):
            src = tag.get("src") or tag.get("href")
            if src:
                full_url = urljoin(base_url, src)
                if self._is_in_scope(full_url):
                    links.append(full_url)

        return links

    def _extract_forms(self, page_url: str, soup: BeautifulSoup):
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = urljoin(page_url, action) if action else page_url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                }
                if input_data["name"]:
                    inputs.append(input_data)

            form_data = FormData(
                url=page_url,
                action=action_url,
                method=method,
                inputs=inputs,
            )
            self.forms.append(form_data)

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        return parsed.netloc == self.base_domain

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # Normalize: remove trailing slash, lowercase
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"
