"""
API Fuzzer — descobre e testa endpoints REST automaticamente.
Extrai rotas de JS, testa verbos HTTP e verifica responses anômalas.
"""
import re, requests, warnings
from core.utils import print_status

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Padrões de endpoints em bundles JS
API_PATTERNS = [
    re.compile(r'["\'](/(?:api|v\d+|rest|service)[^\s"\'<>]{1,80})["\']'),
    re.compile(r'(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(\s*["\']([/][^\s"\']+)["\']'),
    re.compile(r'baseURL\s*[:=]\s*["\']([^"\']+)["\']'),
]

HTTP_VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

INTERESTING_STATUS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    405: "Method Not Allowed",
    500: "Internal Server Error",
}


class APIFuzzer:
    def __init__(self, target: str, context=None):
        self.target  = target
        self.context = context
        self.results = {
            "discovered_endpoints": [],
            "verb_tampering":       [],
            "exposed_endpoints":    [],
        }

    def _req(self, url, method="GET"):
        try:
            return requests.request(
                method, url, timeout=6, verify=False,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
        except Exception:
            return None

    def extract_from_js(self, pages: list) -> list[str]:
        """Extrai endpoints de arquivos JS."""
        endpoints = set()
        for page in pages:
            if not page["url"].endswith(".js") and "javascript" not in page["headers"].get("Content-Type",""):
                continue
            for pattern in API_PATTERNS:
                for match in pattern.findall(page["html"]):
                    if isinstance(match, tuple):
                        match = match[0]
                    if match.startswith("/") and len(match) > 2:
                        full = self.target.rstrip("/") + match
                        endpoints.add(full)
        return list(endpoints)

    def test_verb_tampering(self, endpoints: list):
        """Testa todos os verbos HTTP em cada endpoint."""
        print_status(f"Verb Tampering em {len(endpoints)} endpoints...", "INFO")
        for url in endpoints[:20]:
            verb_results = {}
            for verb in HTTP_VERBS:
                r = self._req(url, verb)
                if r:
                    verb_results[verb] = r.status_code

            # Anomalia: DELETE/PUT retorna 200 quando GET retorna 200
            if verb_results.get("GET") == 200:
                for v in ("DELETE", "PUT", "PATCH"):
                    if verb_results.get(v) == 200:
                        finding = {
                            "url":      url,
                            "issue":    f"Verb Tampering: {v} aceito sem restrição",
                            "severity": "HIGH",
                            "evidence": str(verb_results),
                            "source":   "APIFuzzer",
                        }
                        self.results["verb_tampering"].append(finding)
                        if self.context:
                            self.context.add_finding(finding)
                        print_status(f"VERB TAMPERING {v} em {url}", "CRIT")

    def probe_common_apis(self):
        """Testa endpoints REST comuns que podem estar expostos."""
        common = [
            "/api/users", "/api/admin", "/api/config", "/api/keys",
            "/api/debug", "/api/v1/users", "/api/v2/users",
            "/api/health", "/api/status", "/api/metrics",
            "/api/docs", "/api/swagger", "/swagger.json",
            "/swagger-ui.html", "/openapi.json", "/api-docs",
            "/v1/", "/v2/", "/v3/",
            "/.well-known/security.txt",
            "/server-status", "/server-info",
        ]
        print_status("Probing common API endpoints...", "INFO")
        for path in common:
            url = self.target.rstrip("/") + path
            r   = self._req(url)
            if r and r.status_code in (200, 401, 403):
                entry = {
                    "url":    url,
                    "status": r.status_code,
                    "size":   len(r.text),
                    "ct":     r.headers.get("Content-Type",""),
                }
                self.results["discovered_endpoints"].append(entry)
                if self.context:
                    self.context.add_url(url)

                # 200 em /api/users ou /api/admin é crítico
                if r.status_code == 200 and any(s in path for s in ("users","admin","config","keys","debug")):
                    finding = {
                        "url":      url,
                        "issue":    f"Endpoint sensível exposto sem autenticação: {path}",
                        "severity": "HIGH",
                        "source":   "APIFuzzer",
                    }
                    self.results["exposed_endpoints"].append(finding)
                    if self.context:
                        self.context.add_finding(finding)
                    print_status(f"Endpoint exposto: {url}", "CRIT")

    def run(self, pages: list) -> dict:
        js_endpoints = self.extract_from_js(pages)
        if js_endpoints:
            print_status(f"APIFuzzer: {len(js_endpoints)} endpoints extraídos de JS.", "SUCCESS")
            self.results["discovered_endpoints"].extend([{"url": e, "source": "JS"} for e in js_endpoints])
            self.test_verb_tampering(js_endpoints)
        self.probe_common_apis()
        return self.results
