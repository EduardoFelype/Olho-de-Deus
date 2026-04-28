"""
Crawler profundo — Pipeline 2.
Coleta links, JS files, forms, robots.txt e sitemap.xml.
"""
import requests, warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.utils import print_status
from config import Config

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
HEADERS = {"User-Agent": Config.USER_AGENT}


class Crawler:
    def __init__(self, target, max_pages=None, context=None):
        self.target       = target
        self.max_pages    = max_pages or Config.MAX_PAGES
        self.context      = context
        self._base_netloc = urlparse(target).netloc
        self._visited     = set()
        self._queue       = [target]

    def _fetch(self, url):
        try:
            return requests.get(url, headers=HEADERS, timeout=8, verify=False)
        except Exception:
            return None

    def _is_internal(self, url):
        return self._base_netloc in urlparse(url).netloc

    def _seed_from_robots(self):
        r = self._fetch(urljoin(self.target, "/robots.txt"))
        if r and r.status_code == 200:
            for line in r.text.splitlines():
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":",1)[1].strip()
                    if path and path != "/":
                        self._queue.append(urljoin(self.target, path))

    def _seed_from_sitemap(self):
        r = self._fetch(urljoin(self.target, "/sitemap.xml"))
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, "xml")
            for loc in soup.find_all("loc"):
                url = loc.text.strip()
                if self._is_internal(url):
                    self._queue.append(url)

    def crawl(self):
        pages = []
        self._seed_from_robots()
        self._seed_from_sitemap()

        while self._queue and len(pages) < self.max_pages:
            url = self._queue.pop(0)
            if url in self._visited:
                continue
            self._visited.add(url)
            if self.context:
                self.context.add_url(url)

            r = self._fetch(url)
            if not r:
                continue

            page = {
                "url":     url,
                "status":  r.status_code,
                "html":    r.text,
                "headers": dict(r.headers),
                "forms":   [],
            }

            if "html" in r.headers.get("Content-Type",""):
                soup = BeautifulSoup(r.text, "html.parser")

                # Links internos
                for tag in soup.find_all("a", href=True):
                    full = urljoin(url, tag["href"])
                    if self._is_internal(full) and full not in self._visited:
                        self._queue.append(full)

                # Forms (usados pelo exploiter)
                for form in soup.find_all("form"):
                    page["forms"].append({
                        "action": urljoin(url, form.get("action", url)),
                        "method": form.get("method","get").upper(),
                        "inputs": [i.get("name") for i in form.find_all("input") if i.get("name")]
                    })

                # JS files
                for script in soup.find_all("script", src=True):
                    js_url = urljoin(url, script["src"])
                    if js_url not in self._visited:
                        r_js = self._fetch(js_url)
                        if r_js:
                            self._visited.add(js_url)
                            pages.append({
                                "url": js_url, "status": r_js.status_code,
                                "html": r_js.text, "headers": dict(r_js.headers), "forms": []
                            })

            pages.append(page)

        print_status(f"Crawler: {len(pages)} páginas coletadas.", "SUCCESS")
        return pages
